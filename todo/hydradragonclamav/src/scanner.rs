use crate::atomscan::InlineVerifyCtx;
use crate::database::{Database, OffsetAnchor, SourceLocation};
use crate::logical::Subsignature;
use crate::pattern::Pattern;
use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

thread_local! {
    /// Per-thread reusable atom-filter scratch. The scan pipeline runs many
    /// buffers per file (every extracted APK entry is its own context), each
    /// needing per-slot count/offset arrays sized to the whole signature DB.
    /// Reusing one `AtomScratch` per thread avoids reallocating those large
    /// arrays on every buffer; `AtomScratch::scan` resets them each call.
    static ATOM_SCRATCH: RefCell<crate::atomscan::AtomScratch> =
        RefCell::new(crate::atomscan::AtomScratch::new());
}

/// Per-scan timing breakdown: ClamAV and per-YARA-ruleset elapsed nanoseconds.
#[derive(Clone, Debug, Default)]
pub struct TimingBreakdown {
    pub clamav_ns: u128,
    pub yara_per_engine: Vec<(String, u128)>,
}

impl TimingBreakdown {
    /// Merge another breakdown into this one (add ClamAV time, append YARA entries).
    pub fn accumulate(&mut self, other: TimingBreakdown) {
        self.clamav_ns = self.clamav_ns.saturating_add(other.clamav_ns);
        self.yara_per_engine.extend(other.yara_per_engine);
    }
}

#[derive(Debug)]
pub struct Engine {
    pub database: Database,
    /// Binary-Fuse16 atom/counter/threshold filter database: every signature's
    /// (and logical subsignature's) atoms are indexed into Bf16 set-membership
    /// filters at load time. Scanning promotes a slot directly off its hit
    /// counter reaching threshold — there is byte-level re-verification of
    /// the matched atom or its owning pattern (see `atomfilter.rs`).
    atomfilter_db: crate::atomfilter::AtomFilterDb,
    /// YARA-x engines for scanning with compiled YARA rules (Android-relevant
    /// types only, see `yara_scan::is_target_allowed`). Multiple rulesets can be
    /// loaded (e.g. clean / valhalla / AndroidOS); all are run.
    pub yara: Vec<crate::yara_scan::YaraEngine>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub scan_archives: bool,
    pub max_recursion: usize,
    pub max_child_size: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_archives: true,
            max_recursion: 16,
            max_child_size: 650 * 1024 * 1024,
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
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    );
}
#[cfg(target_os = "android")]
const ANDROID_LOG_INFO: std::os::raw::c_int = 4;

#[cfg(target_os = "android")]
fn android_log(msg: &str) {
    use std::ffi::CString;
    let (Ok(tag), Ok(text)) = (
        CString::new("HydraDragon-RustTiming"),
        CString::new(msg),
    ) else {
        return;
    };
    unsafe { __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr()) };
}

/// Writes a timing/diagnostic logcat line.
///
/// On Android this formats the message and writes it to logcat. On every
/// other target `android_log` is a no-op, so the previous version still paid
/// for building the `String` via `format!()` on every call (including the
/// unconditional per-scan summary in `scan_context`) only to throw it away.
/// Gating at the macro level means the format arguments are never evaluated
/// off-Android — `#[cfg(...)]` on the statement compiles the non-Android
/// branch out entirely.
macro_rules! rust_timing_log {
    ($($arg:tt)*) => {
        #[cfg(target_os = "android")]
        {
            android_log(&format!($($arg)*));
        }
        #[cfg(not(target_os = "android"))]
        {
            eprintln!("{}", format!($($arg)*));
        }
    };
}

/// RAII guard: logs a warning when the elapsed time exceeds `threshold_ms`
/// on drop. Wrap at function entry: `let _slow = SlowAlert::new("fn_name", 100);`.
pub struct SlowAlert {
    name: &'static str,
    threshold_ms: u64,
    start: Instant,
}

impl SlowAlert {
    pub fn new(name: &'static str, threshold_ms: u64) -> Self {
        SlowAlert { name, threshold_ms, start: Instant::now() }
    }
}

impl Drop for SlowAlert {
    fn drop(&mut self) {
        let ms = self.start.elapsed().as_millis() as u64;
        if ms > self.threshold_ms {
            rust_timing_log!("[SLOW-CODE] {} took {}ms (threshold {}ms)", self.name, ms, self.threshold_ms);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKind {
    Extended,
    Logical,
    Container,
    /// Phishing heuristic (`.pdb`/`.gdb`/`.wdb` driven spoofed-domain check).
    Phishing,
    /// YARA-x rule match.
    Yara,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanView {
    Raw,
}

pub(crate) struct ScanContext<'a> {
    pub data: &'a [u8],
    /// Target derived from `.ftm` file-type magic.
    pub detected_target: Option<u32>,
    pub object_path: &'a str,
    pub view: ScanView,
    /// ClamAV `CL_TYPE_*` of this object's IMMEDIATE parent container (the type
    /// of the archive it was extracted from), or `None` at the top level. Used to
    /// evaluate logical signatures' `Container:` TDB constraint, mirroring
    /// ClamAV's `cli_recursion_stack_get_type(ctx, -2)`.
    pub container_type: Option<&'static str>,
    /// Container metadata for `.cdb` signature matching.
    pub container_size_real: Option<u64>,
    pub container_file_pos: Option<u64>,
    pub container_entry_name: Option<String>,
    /// The file's image fuzzy hash (perceptual pHash), computed lazily once and
    /// only when a `fuzzy_img#` subsignature is actually evaluated. `None` inside
    /// the cell means "computed, not a decodable image".
    pub image_fuzzy_hash: std::cell::OnceCell<Option<[u8; 8]>>,
}

impl ScanContext<'_> {
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
}

/// Reusable per-call buffers for `scan_one_logical` — the outer `scan_logical`
/// allocates them once and passes `&mut` so the backing store is reused across
/// every candidate, avoiding ~4 heap allocations per logical-sig evaluation.
struct LogicalScanBufs {
    counts: Vec<usize>,
    last_offsets: Vec<Option<usize>>,
    evaluated: Vec<bool>,
    /// Per-subsig timing/shape breakdown collected during the last
    /// `scan_one_logical` call, for the `[SIG-DETAIL]` log — cleared and
    /// refilled every call, only formatted into a log line when the caller
    /// decides the signature was slow enough to be worth the detail.
    detail: Vec<SubsigDetail>,
    /// Reusable bitmap, one bit per logical signature, marking the signatures
    /// whose atom slot(s) reached threshold this buffer. Only these are
    /// evaluated — signatures without indexable atoms are never visited.
    /// Cleared (filled false) at the start of each buffer. Resized once and
    /// reused across buffers, so no per-buffer allocation.
    candidate_set: Vec<bool>,
}

/// One phase-1 subsig's contribution to a slow logical-signature scan.
struct SubsigDetail {
    subsig: usize,
    /// "gate", "restricted" (window-restricted via prefilter hints), or "full" (whole
    /// buffer scanned, no hints available).
    kind: &'static str,
    elapsed_us: u128,
    count: usize,
    ranges: usize,
}

impl Engine {
    /// AtomFilterDb heap breakdown, for `--mem-stats` profiling.
    pub fn prefilter_mem_report(&self) -> String {
        let db = &self.atomfilter_db;
        format!(
            "slots={} ext_slots={} log_sigs={}",
            db.slots.len(),
            db.ext_slot.len(),
            db.log_subsig_slots.len(),
        )
    }

    /// Serialized atomfilter cache bytes for reuse on next process start.
    pub fn atomfilter_cache_bytes(&self) -> Vec<u8> {
        self.atomfilter_db.to_bytes()
    }

    /// Load from a filesystem directory (original path-based loading).
    pub fn from_database_dir(path: impl AsRef<Path>) -> io::Result<(Self, crate::LoadReport)> {
        let path = path.as_ref();
        let t0 = Instant::now();
        let (mut database, mut report) = Database::load_dir(path)?;
        rust_timing_log!("from_database_dir :: load_dir={}ms files={} ext={} logical={} container={}",
            t0.elapsed().as_millis(), report.files_seen, database.extended.len(), database.logical.len(),
            database.container.len());
        let bc = crate::bytecode::BytecodeSet::load_from_dir(path);
        Ok(Self::finish_engine_init(&mut database, &mut report, bc, t0, None))
    }

    /// Load from a pre-read map of filename → file contents (AAssetManager path).
    /// The caller reads every asset file into `HashMap<filename, Vec<u8>>` and
    /// passes it here — no filesystem I/O needed at init time.
    pub fn from_bytes_map(
        files: &std::collections::HashMap<String, Vec<u8>>,
    ) -> (Self, crate::LoadReport) {
        let t0 = Instant::now();
        let (mut database, mut report) = Database::from_bytes_map(files);
        rust_timing_log!("from_bytes_map :: load_dir={}ms files={} ext={} logical={} container={}",
            t0.elapsed().as_millis(), report.files_seen, database.extended.len(), database.logical.len(),
            database.container.len());
        let bc = crate::bytecode::BytecodeSet::from_bytes_map(files);
        let (engine, report) = Self::finish_engine_init(&mut database, &mut report, bc, t0, None);
        (engine, report)
    }

    /// Like `from_bytes_map` but uses a pre-built atomfilter cache.
    pub fn from_bytes_map_with_atomfilter(
        files: &std::collections::HashMap<String, Vec<u8>>,
        atomfilter_cache: crate::atomfilter::AtomFilterDb,
    ) -> (Self, crate::LoadReport) {
        let t0 = Instant::now();
        let (mut database, mut report) = Database::from_bytes_map(files);
        rust_timing_log!("from_bytes_map :: load_dir={}ms files={} ext={} logical={} container={}",
            t0.elapsed().as_millis(), report.files_seen, database.extended.len(), database.logical.len(),
            database.container.len());
        let bc = crate::bytecode::BytecodeSet::from_bytes_map(files);
        let (engine, report) = Self::finish_engine_init(&mut database, &mut report, bc, t0, Some(atomfilter_cache));
        (engine, report)
    }

    /// Shared bytecode + prefilter init used by both `from_database_dir` and
    /// `from_bytes_map`.
    fn finish_engine_init(
        database: &mut Database,
        report: &mut crate::LoadReport,
        bc: crate::bytecode::BytecodeSet,
        t0: std::time::Instant,
        atomfilter_cache: Option<crate::atomfilter::AtomFilterDb>,
    ) -> (Self, crate::LoadReport) {
        let t_bc = Instant::now();
        report.bytecodes_loaded = bc.report.loaded;
        for prog in bc.bytecodes {
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
        rust_timing_log!("from_database_dir :: bytecode={}ms loaded={}", t_bc.elapsed().as_millis(), report.bytecodes_loaded);
        let t_pf = Instant::now();
        let atomfilter_db = match atomfilter_cache {
            Some(cache) => {
                rust_timing_log!("atomfilter_build :: using cache");
                cache
            }
            None => {
                let db = crate::atomfilter_build::AtomFilterBuilder::build(database);
                rust_timing_log!("from_database_dir :: atomfilter_build={}ms slots={}", t_pf.elapsed().as_millis(), db.slots.len());
                db
            }
        };
        rust_timing_log!("from_database_dir :: TOTAL={}ms", t0.elapsed().as_millis());
        let database = std::mem::take(database);
        (Self { database, atomfilter_db, yara: Vec::new() }, std::mem::take(report))
    }

    /// Replace all YARA rulesets with a single one compiled from source.
    /// Returns `None` when the rules file cannot be loaded or compiled.
    pub fn load_yara_rules(&mut self, path: impl AsRef<Path>) -> Option<()> {
        let engine = crate::yara_scan::YaraEngine::from_source_file(path)?;
        self.yara = vec![engine];
        Some(())
    }

    /// Add a YARA ruleset compiled from source (keeps existing ones).
    pub fn add_yara_source_file(&mut self, path: impl AsRef<Path>) -> Option<()> {
        self.yara
            .push(crate::yara_scan::YaraEngine::from_source_file(path)?);
        Some(())
    }

    /// Add a pre-compiled `.yrc` YARA ruleset (keeps existing ones). Far faster
    /// on-device than compiling source.
    pub fn add_compiled_yara_file(&mut self, path: impl AsRef<Path>) -> Option<()> {
        self.yara
            .push(crate::yara_scan::YaraEngine::from_compiled_file(path)?);
        Some(())
    }

    /// Add an already-loaded YARA engine (parsed from compiled bytes).
    /// Useful when the `.yrc` was read + parsed in a background thread to
    /// parallelise the init phase — the caller passes back the ready engine
    /// and this method just pushes it onto the engine list (no I/O, no parse).
    pub fn add_compiled_yara(&mut self, engine: crate::yara_scan::YaraEngine) {
        self.yara.push(engine);
    }

    pub fn scan_path(
        &self,
        path: impl AsRef<Path>,
        options: ScanOptions,
    ) -> io::Result<Vec<ScanMatch>> {
        let path = path.as_ref();
        let data = fs::read(path)?;
        Ok(self.scan_bytes_named(&data, &path.display().to_string(), options, &[]))
    }

    pub fn scan_bytes(&self, data: &[u8], options: ScanOptions) -> Vec<ScanMatch> {
        self.scan_bytes_named(data, "root", options, &[])
    }

    pub fn scan_bytes_named(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
    ) -> Vec<ScanMatch> {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        self.scan_object(data, object_path, None, None, None, None, 0, options, module_meta, &mut state, &mut None, false, false);
        state.matches
    }

    /// Same as `scan_bytes_named` but also returns a per-engine timing breakdown
    /// (ClamAV + each YARA ruleset) in nanoseconds.
    pub fn scan_bytes_named_with_breakdown(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
    ) -> (Vec<ScanMatch>, TimingBreakdown) {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        let mut breakdown = TimingBreakdown::default();
        self.scan_object(data, object_path, None, None, None, None, 0, options, module_meta, &mut state, &mut Some(&mut breakdown), false, false);
        (state.matches, breakdown)
    }

    /// Run only the ClamAV engine (prefilter + extended + logical + phishing),
    /// skipping all YARA-x rulesets. The counterpart to
    /// [`scan_yara_only_with_breakdown`] — used by the parallel scan pipeline so
    /// ClamAV and YARA can run on separate threads and overlap instead of being
    /// evaluated back-to-back on one thread inside `scan_object`.
    pub fn scan_clamav_only_with_breakdown(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
    ) -> (Vec<ScanMatch>, TimingBreakdown) {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        let mut breakdown = TimingBreakdown::default();
        self.scan_object(data, object_path, None, None, None, None, 0, options, module_meta, &mut state, &mut Some(&mut breakdown), false, true);
        (state.matches, breakdown)
    }

    /// Same as `scan_bytes_named_with_breakdown` but accepts container metadata
    /// for `.cdb` container-signature matching. Use when scanning an extracted
    /// child buffer whose parent archive metadata (container type, compressed
    /// size, file offset, entry name) is known.
    pub fn scan_bytes_named_with_container(
        &self,
        data: &[u8],
        object_path: &str,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
        container_type: Option<&'static str>,
        container_size_real: Option<u64>,
        container_file_pos: Option<u64>,
        container_entry_name: Option<String>,
    ) -> (Vec<ScanMatch>, TimingBreakdown) {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        let mut breakdown = TimingBreakdown::default();
        self.scan_object(data, object_path, container_type, container_size_real, container_file_pos, container_entry_name, 0, options, module_meta, &mut state, &mut Some(&mut breakdown), false, false);
        (state.matches, breakdown)
    }

    /// Run only YARA-x rules (skip ClamAV signatures + phishing heuristic).
    /// Used by the streaming extract+scan pipeline where ClamAV was already
    /// run per-buffer during extraction, and only module_meta-dependent YARA
    /// rules need a second pass after Phase 2 builds hydradragon
    /// module metadata.
    pub fn scan_yara_only_with_breakdown(
        &self,
        data: &[u8],
        object_path: &str,
        module_meta: &[(&str, &[u8])],
    ) -> (Vec<ScanMatch>, TimingBreakdown) {
        let mut state = ScanState {
            matches: Vec::new(),
        };
        let mut breakdown = TimingBreakdown::default();
        self.scan_object(data, object_path, None, None, None, None, 0, ScanOptions::default(), module_meta, &mut state, &mut Some(&mut breakdown), true, false);
        (state.matches, breakdown)
    }

    fn scan_object(
        &self,
        data: &[u8],
        object_path: &str,
        container_type: Option<&'static str>,
        container_size_real: Option<u64>,
        container_file_pos: Option<u64>,
        container_entry_name: Option<String>,
        _depth: usize,
        options: ScanOptions,
        module_meta: &[(&str, &[u8])],
        state: &mut ScanState,
        timing: &mut Option<&mut TimingBreakdown>,
        skip_clamav: bool,
        skip_yara: bool,
    ) {
        let _slow = SlowAlert::new("scan_object", 200);
        if data.len() > options.max_child_size {
            return;
        }

        // Skip raw scan for archives we cannot extract — scanning compressed
        // random bytes against 500k+ signatures triggers pathological backtracking
        // in the gap-matching loop. The actual unpacker in hydradragonextractor
        // handles only gz/zip/xz/lzma/tar/7z; anything else is skipped here.
        // Checked BEFORE type detection: no point running the file-type magic
        // scan (linear over every loaded `.ftm` pattern) on bytes we're about
        // to reject outright.
        // YARA-only scan doesn't have this backtracking issue, so skip the check.
        if !skip_clamav && is_unsupported_archive(data) {
            return;
        }

        let detected_target = if !self.database.file_type_magic.is_empty()
        {
            self.detect_clamav_type(data).and_then(clamav_type_to_target)
        } else {
            None
        };

        let ctx = ScanContext {
            data,
            detected_target,
            object_path,
            view: ScanView::Raw,
            container_type,
            container_size_real,
            container_file_pos,
            container_entry_name,
            image_fuzzy_hash: Default::default(),
        };

        let confident_target = detected_target.or_else(|| detect_builtin_target(&ctx));

        // Run the ClamAV engine (prefilter + extended + logical) on files
        // whose type is either unknown or positively identified as a supported
        // type.  Known-but-unsupported desktop targets (OLE2, Mail, Mach-O,
        // Java, …) are skipped outright — this avoids paying for the whole-buffer
        // atom prefilter only to have `target_matches` reject every candidate.
        if !skip_clamav {
            if confident_target.is_some() && clamav_target_allowed(confident_target)
                || confident_target.is_none() && is_text_like(ctx.data)
            {
                // Time ClamAV scan_context
                let t_clamav = timing.as_ref().map(|_| Instant::now());
                self.scan_context(&ctx, &mut state.matches);
                if let (Some(t), Some(bt)) = (t_clamav, timing.as_mut()) {
                    bt.clamav_ns = bt.clamav_ns.saturating_add(t.elapsed().as_nanos());
                }
            }

            // Phishing heuristic: harvest `<a href>` link pairs from HTML/email and
            // flag spoofed protected domains (.pdb/.gdb gated by .wdb allow list).
            // Only meaningful for HTML, and only when a protected-domain DB is loaded.
            if !self.database.phishing.protected.is_empty()
                && looks_like_html(data)
            {
                self.scan_phishing(data, object_path, &mut state.matches);
            }
        }

        // YARA-x scan for Android-relevant file types — run every loaded ruleset,
        // timing each YARA ruleset individually.
        if !skip_yara
            && !self.yara.is_empty()
            && crate::yara_scan::is_target_allowed(confident_target)
        {
            for yara in &self.yara {
                // Module-dependent rulesets (hydradragon/hips) can't evaluate
                // without their JSON metadata, which only exists AFTER the
                // streaming extract pass. Skip them here when no metadata is
                // present — Phase 3 rescans them exactly once with metadata.
                // This ensures every ruleset is scanned once, not twice.
                if yara.module_dependent && module_meta.is_empty() {
                    continue;
                }
                let t_yara = timing.as_ref().map(|_| Instant::now());
                for m in yara.scan(data, object_path, module_meta) {
                    state.matches.push(m);
                }
                if let (Some(t), Some(bt)) = (t_yara, timing.as_mut()) {
                    bt.yara_per_engine.push((yara.name.clone(), t.elapsed().as_nanos()));
                }
            }
        }

        // NOTE: ZIP member extraction is deliberately NOT done here anymore.
        // The caller (hydradragonandroid's collect_buffers) already walks every
        // archive recursively via hydradragonextractor and hands each extracted
        // file to scan_bytes_named as its own whole buffer/context. Re-splitting
        // a zip-shaped buffer into its members again in here duplicated that
        // work — every nested zip got extracted AND scanned twice, member by
        // member, producing a flood of near-empty scan_context calls for tiny
        // entries instead of one scan per whole buffer. Each buffer is now
        // scanned as a single whole context, exactly once.
    }

    /// Run the phishing heuristic over an HTML/email object's link pairs,
    /// appending one `ScanMatch` per detected spoof (`Heuristics.Phishing.*`).
    fn scan_phishing(
        &self,
        data: &[u8],
        object_path: &str,
        matches: &mut Vec<ScanMatch>,
    ) {
        for hit in self.database.phishing.scan_html(data) {
            matches.push(ScanMatch {
                name: hit.name.to_string(),
                kind: SignatureKind::Phishing,
                source: hit.source,
                object_path: object_path.to_string(),
                view: ScanView::Raw,
            });
        }
    }

    /// Identify the ClamAV file type (`CL_TYPE_*`) of `data` via `.ftm` magic.
    /// Detect the ClamAV target type of `data` using the loaded file-type magic
    /// database — the exact same detection the scanner uses internally. Returns
    /// the ClamAV target number, or `None` for "any file"/unrecognised.
    ///
    /// Combine with [`crate::yara_scan::is_target_allowed`] to decide whether a
    /// file is a supported/scannable type before scanning it.
    pub fn detect_target(&self, data: &[u8]) -> Option<u32> {
        self.detect_clamav_type(data).and_then(clamav_type_to_target)
    }

    fn detect_clamav_type(&self, data: &[u8]) -> Option<&str> {
        for magic in &self.database.file_type_magic {
            let ranges = magic.offset.scan_ranges(data.len());
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
        matches: &mut Vec<ScanMatch>,
    ) {
        let _slow = SlowAlert::new("scan_context", 200);
        if ctx.data.is_empty() { return; }

        // One rolling-hash sweep builds per-slot hit counts for this buffer;
        // both phases then promote slots that reached their threshold.
        //
        // The scratch buffers (per-slot counts/offsets, sized to the whole
        // signature DB) are held in a thread-local and reused across every
        // buffer this thread scans. Allocating them fresh per buffer — as an
        // APK with hundreds of nested entries does — was hundreds of large
        // heap alloc/free cycles proportional to DB size. `AtomScratch::scan`
        // still fully resets them each call, so results are unchanged. The
        // thread-local borrow is held for the whole `scan_context` so the
        // extended/logical passes read the counts in place with no copy.
        ATOM_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let file_type_target = ctx.detected_target
                .or_else(|| detect_builtin_target(ctx))
                .unwrap_or(0);
            let t0 = Instant::now();
            // Build slot→patterns mapping for inline verification.
            // slot_patterns[slot_id] = patterns to verify (empty if no Body subsig).
            let mut slot_patterns: Vec<&[Pattern]> = Vec::with_capacity(self.atomfilter_db.slots.len());
            slot_patterns.resize(self.atomfilter_db.slots.len(), &[]);
            for (slot_id, slot) in self.atomfilter_db.slots.iter().enumerate() {
                if let crate::atomfilter::SlotTarget::LogicalSubsig { sig_index, subsig_index, .. } = slot.target {
                    let Some(sig) = self.database.logical.get(sig_index as usize) else { continue };
                    let Some(subsig) = sig.subsignatures.get(subsig_index as usize) else { continue };
                    if let Subsignature::Body { patterns, .. } = subsig {
                        slot_patterns[slot_id] = &patterns[..];
                    }
                }
            }
            let mut verify_results = vec![false; self.atomfilter_db.slots.len()];
            let verify_ctx = InlineVerifyCtx {
                slot_patterns: slot_patterns.as_slice(),
                hay: ctx.data,
            };
            let slot_counts = scratch.scan_with_verify(
                &self.atomfilter_db, ctx.data, file_type_target,
                &verify_ctx, &mut verify_results,
            );
            let t1 = Instant::now();
            self.scan_extended(ctx, matches, &slot_counts);
            let t2 = Instant::now();
            self.scan_logical(ctx, matches, &slot_counts, &verify_results);
            let t3 = Instant::now();
            rust_timing_log!(
                "scan_context :: {}KB view={:?} atomscan={}ms ext_scan={}ms log_scan={}ms",
                ctx.data.len() / 1024,
                ctx.view,
                (t1 - t0).as_millis(),
                (t2 - t1).as_millis(),
                (t3 - t2).as_millis(),
            );
        });

        // ── Container metadata signatures (.cdb) ──────────────────────────
        if let (Some(sr), Some(fp)) = (ctx.container_size_real, ctx.container_file_pos) {
            for sig in &self.database.container {
                if sig.has_filename && ctx.container_entry_name.is_none() {
                    continue;
                }
                if !sig.container_type.matches_container(ctx.container_type) {
                    continue;
                }
                if !sig.size_real.matches(sr) {
                    continue;
                }
                if !sig.file_pos.matches(fp) {
                    continue;
                }
                matches.push(ScanMatch {
                    name: sig.name.to_string(),
                    kind: SignatureKind::Container,
                    source: sig.source.clone(),
                    object_path: ctx.object_path.to_string(),
                    view: ctx.view,
                });
            }
        }
    }


    fn scan_extended(
        &self,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        slot_counts: &crate::atomscan::SlotCounts,
    ) {
        for (si, ext_slot) in self.atomfilter_db.ext_slot.iter().enumerate() {
            if !crate::atomscan::ext_matched(*ext_slot, &self.atomfilter_db.slots, slot_counts) {
                continue;
            }
            if !target_matches(self.database.extended[si].target, ctx, self.database.ext_name(&self.database.extended[si])) {
                continue;
            }
            self.scan_one_extended(si, ctx, matches);
        }
    }

    /// Evaluate a single extended signature whose atom slot reached threshold.
    fn scan_one_extended(
        &self,
        si: usize,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
    ) {
        let signature = &self.database.extended[si];
        if !target_matches(signature.target, ctx, self.database.ext_name(signature)) {
            return;
        }
        if matches!(
            signature.offset.anchor,
            OffsetAnchor::Unsupported(_) | OffsetAnchor::MacroGroup(_)
            | OffsetAnchor::VersionInfo
        ) {
            return;
        }
        let ranges = signature.offset.scan_ranges(ctx.data.len());
        if ranges.is_empty() {
            return;
        }
        let t_ext = std::time::Instant::now();
        // Extended-signature callers only need to know whether a pattern
        // matched at least once — `count_all` used to tally every occurrence
        // across the whole buffer, which is unnecessarily expensive on
        // repetitive/padded data. `find_all(.., 1)` stops at the first hit,
        // and we break out of the outer loop as soon as any pattern matches.
        let mut matched = false;
        for pattern in &signature.patterns {
            if !pattern.find_all(ctx.data, &ranges, 1).is_empty() {
                matched = true;
                break;
            }
        }
        let count = usize::from(matched);
        let ms = t_ext.elapsed().as_millis();
        if ms >= 20 {
            rust_timing_log!(
                "[SLOW-EXT] {ms}ms {} ({}:{})",
                self.database.ext_name(signature),
                signature.source.path.display(),
                signature.source.line,
            );
        }
        if count > 0 {
            matches.push(ScanMatch {
                name: self.database.ext_name(signature).to_string(),
                kind: SignatureKind::Extended,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
            });
        }
    }

    fn scan_logical(
        &self,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        slot_counts: &crate::atomscan::SlotCounts,
        verify_results: &[bool],
    ) {
        let mut bufs = LogicalScanBufs {
            counts: Vec::new(),
            last_offsets: Vec::new(),
            evaluated: Vec::new(),
            detail: Vec::new(),
            candidate_set: Vec::new(),
        };
        // Hit-driven candidate selection: derive the candidate set straight
        // from the slots that actually reached threshold. A slot whose target
        // is a logical subsig marks that signature as a candidate; extended-sig
        // slots are skipped here (they belong to `scan_extended`). Signatures
        // without indexable atoms are never visited — only atom-gated
        // signatures can become candidates.
        let n_log = self.database.logical.len();
        bufs.candidate_set.clear();
        bufs.candidate_set.resize(n_log, false);
        for (slot_id, slot) in self.atomfilter_db.slots.iter().enumerate() {
            if slot_counts.get(slot_id as crate::atomfilter::SlotId) < slot.threshold {
                continue;
            }
            if let crate::atomfilter::SlotTarget::LogicalSubsig { sig_index, .. } = slot.target {
                let si = sig_index as usize;
                if si < n_log {
                    bufs.candidate_set[si] = true;
                }
            }
        }
        // Signatures where every subsig has no indexable atom (all
        // AutoMatch/External) are never visited by the slot loop — their subsigs
        // return unconditional counts (AutoMatch=1, External=0).  Mark them as
        // candidates so they are still evaluated.
        for (si, sub_slots) in self.atomfilter_db.log_subsig_slots.iter().enumerate() {
            if bufs.candidate_set[si] {
                continue;
            }
            if sub_slots.iter().any(|s| matches!(s, crate::atomfilter::SubsigSlot::AutoMatch)) {
                bufs.candidate_set[si] = true;
            }
        }

        for si in 0..n_log {
            if !bufs.candidate_set[si] {
                continue;
            }
            let t = std::time::Instant::now();
            self.scan_one_logical(si, slot_counts, ctx, matches, &mut bufs, verify_results);
            let ms = t.elapsed().as_millis();
            if ms >= 50 {
                rust_timing_log!("[SLOW-LOG] {ms}ms {}", self.database.logical[si].name);
            }
            if ms >= 20 && !bufs.detail.is_empty() {
                let mut line = format!(
                    "[SIG-DETAIL] {ms}ms {} subsigs=",
                    self.database.logical[si].name
                );
                for d in &bufs.detail {
                    line.push_str(&format!(
                        "[{}:{}:{}us,cnt={},ranges={}]",
                        d.subsig, d.kind, d.elapsed_us, d.count, d.ranges
                    ));
                }
                rust_timing_log!("{}", line);
            }
        }
    }

    /// Evaluate a single logical signature using the pre-computed slot counts.
    ///
    /// `verify_results` \[slot_id] = true if the atom pattern was verified inline
    /// during the atom sweep.  When `body_count_limit == 1` the per‑subsig
    /// `count_all` re‑scan can be skipped for these slots, saving a redundant
    /// full‑buffer pattern scan.
    fn scan_one_logical(
        &self,
        si: usize,
        slot_counts: &crate::atomscan::SlotCounts,
        ctx: &ScanContext<'_>,
        matches: &mut Vec<ScanMatch>,
        bufs: &mut LogicalScanBufs,
        verify_results: &[bool],
    ) {
        let signature = &self.database.logical[si];
        if !target_matches(signature.target, ctx, &signature.name) {
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
        // NumberOfSections, EntryPoint, and IconGroup are PE(Windows-executable)
        // -only TDB fields — this scanner never parses PE headers (PE isn't an
        // Android-relevant format and isn't in `CLAMAV_ALLOWED_TARGETS`), so
        // there's no way to evaluate these constraints. Skip rather than fire
        // unconditionally: firing without the constraint would turn a
        // PE-specific signature into a false positive on non-PE content.
        if signature.nos.is_some() || signature.ep.is_some()
            || signature.icongrp1.is_some() || signature.icongrp2.is_some()
        {
            return;
        }
        let subsigs = &signature.subsignatures;
        let n = subsigs.len();

        // Populate initial counts from slot assignments: Body subsigs already
        // have their hit count from the atomscan sweep; External subsigs (Pcre,
        // ByteCompare, Fuzzy) start at 0 and are filled in below.
        bufs.counts.clear();
        bufs.counts.resize(n, 0);
        let sub_slots = if si < self.atomfilter_db.log_subsig_slots.len() {
            Some(&self.atomfilter_db.log_subsig_slots[si])
        } else {
            None
        };
        if let Some(slots) = sub_slots {
            crate::atomscan::logical_initial_counts_into(
                &mut bufs.counts,
                slots,
                &self.atomfilter_db.slots,
                slot_counts,
            );
        }
        bufs.last_offsets.clear();
        bufs.last_offsets.resize(n, None);
        // Populate last_offsets from slot assignments for ByteCompare anchoring.
        if let Some(slots) = sub_slots {
            let limit = slots.len().min(n);
            for (i, slot) in slots[..limit].iter().enumerate() {
                if let crate::atomfilter::SubsigSlot::Atom(id) = *slot {
                    bufs.last_offsets[i] = slot_counts.last_offset(id);
                }
            }
        }
        bufs.evaluated.clear();
        bufs.evaluated.resize(n, false);
        // Mark Body subsigs as evaluated (their slot counts are already set).
        for (i, subsig) in subsigs.iter().enumerate() {
            if matches!(subsig, Subsignature::Body { .. }) {
                bufs.evaluated[i] = true;
            }
        }
        bufs.detail.clear();
        let counts = &mut bufs.counts;
        let last_offsets = &mut bufs.last_offsets;
        let evaluated = &mut bufs.evaluated;
        let mut expression_count_limit = signature.expression.count_match_limit();
        for subsig in subsigs.iter() {
            if let Subsignature::Pcre(pcre) = subsig {
                expression_count_limit =
                    expression_count_limit.max(pcre.trigger.count_match_limit());
            }
        }
        let needs_full_counts = signature.bytecode.is_some()
            || subsigs
                .iter()
                .any(|subsig| matches!(subsig, Subsignature::ByteCompare(_)));
        let body_count_limit = if needs_full_counts {
            usize::MAX
        } else {
            expression_count_limit
        };
        let pcre_count_limit = if signature.bytecode.is_some() {
            usize::MAX
        } else {
            expression_count_limit
        };

        // Byte-level confirmation for Body subsigs (ClamAV cli_ac_scanbuff): the
        // atom sweep only says "an atom of this subsig MAY be present" — the atom
        // is a truncated, length-bucketed prefix, so an atom hit is a candidate,
        // not a match. Re-scan the real pattern (wildcards, {-N} gaps, ::i) over
        // the subsig's offset ranges and replace the candidate count with the
        // true occurrence count. Without this, a signature whose atom shadow
        // ("mira" for "mirai", "cryp" for "cryptor.c") appears fires spuriously.
        for (i, subsig) in subsigs.iter().enumerate() {
            let Subsignature::Body { offset, patterns } = subsig else {
                continue;
            };
            if counts[i] == 0 {
                continue; // atom absent → cannot match; leave at 0.
            }
            // ── Inline verification fast-path ───────────────────────
            // When body_count_limit == 1 (existence check) and the
            // atom sweep's inline verifier already confirmed the full
            // pattern, skip the redundant count_all re-scans entirely.
            if body_count_limit == 1 {
                if let Some(slots) = sub_slots {
                    if i < slots.len() {
                        if let crate::atomfilter::SubsigSlot::Atom(slot_id) = slots[i] {
                            if verify_results.get(slot_id as usize).copied().unwrap_or(false) {
                                counts[i] = 1;
                                if !signature.expression.can_still_match(counts, evaluated) {
                                    return;
                                }
                                continue;
                            }
                        }
                    }
                }
            }

            let ranges = match offset.as_deref() {
                Some(spec) => {
                    let r = spec.scan_ranges(ctx.data.len());
                    // Unsupported anchor (EP/section/VI): can't compute the range,
                    // stay permissive with a full-buffer scan (avoids a false
                    // negative) than trusting the raw atom count.
                    if r.is_empty() { vec![(0, ctx.data.len())] } else { r }
                }
                None => vec![(0, ctx.data.len())],
            };
            let t_body = std::time::Instant::now();
            let mut hits = 0usize;
            let mut last = None;
            for pattern in patterns.iter() {
                if hits >= body_count_limit {
                    break;
                }
                let remaining = body_count_limit.saturating_sub(hits);
                let (phits, plast) = pattern.count_all(ctx.data, &ranges, remaining);
                hits += phits;
                if let Some(p) = plast {
                    last = Some(p);
                }
            }
            let body_us = t_body.elapsed().as_micros();
            let kind = if ranges.len() == 1 && ranges[0] == (0, ctx.data.len()) {
                "full"
            } else if ranges.len() < 16 {
                "restricted"
            } else {
                "gate"
            };
            bufs.detail.push(SubsigDetail {
                subsig: i,
                kind,
                elapsed_us: body_us,
                count: hits,
                ranges: ranges.len(),
            });
            counts[i] = hits;
            last_offsets[i] = last;
            // Short-circuit: if the expression can no longer match after this
            // subsig's result, skip remaining subsigs.  Body subsigs are already
            // marked evaluated (set before the loop), and `can_still_match`
            // never prunes through a Compare node (returns true) — so this is
            // always sound.
            if !signature.expression.can_still_match(counts, evaluated) {
                return;
            }
        }

        #[cfg(target_os = "android")]
        let t_debug = std::time::Instant::now();

        // Whether the expression can be trusted to short-circuit on an
        // already-decided outcome (see `is_definitely_matched`/`can_still_match`):
        // unsound through a `Compare` node, since those aren't monotone in the counts.
        // Also unsound whenever a bytecode program is attached: `run_bytecode` below
        // hands the VM the FULL `counts` array (ClamAV's `lsigcnt`), which a program
        // can inspect for any subsig regardless of which branch satisfied the boolean
        // expression — breaking early would feed it stale zeros for un-evaluated
        // subsigs that actually matched.
        #[cfg(target_os = "android")]
        let debug_gate_us = 0u128;

        // Body subsigs are already populated from the atom-scan; nothing more
        // to do for Phase 1 — the counts[] array already reflects them.
        // Short-circuit if the expression is still unsatisfiable.
        if !signature.expression.can_still_match(counts, evaluated) {
            return;
        }

        #[cfg(target_os = "android")]
        let debug_p1_us = 0u128;

        #[cfg(target_os = "android")]
        let t_start_fuzzy = std::time::Instant::now();

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

        #[cfg(target_os = "android")]
        let t_after_fuzzy = std::time::Instant::now();
        #[cfg(target_os = "android")]
        let debug_fuzzy_us = t_after_fuzzy.duration_since(t_start_fuzzy).as_micros();

        // Phase 2: PCRE and byte-compare subsignatures, whose triggers
        // reference the phase-1 body results.
        //
        // On very large buffers (> 10 MB) the regex engine (especially the
        // PikeVM fallback for non-DFA‑friendly patterns) can become
        // pathologically slow — scanning 162 MB of binary APK data for
        // text‑oriented ransomware patterns achieves nothing while costing
        // 100+ ms per PCRE.  We cap the searchable region to the first
        // `PCRE_MAX_SCAN_BYTES` bytes of the buffer; content beyond that
        // is almost certainly not a text‑mode indicator.
        const PCRE_MAX_SCAN_BYTES: usize = 10_000_000;
        let pcre_needle = if ctx.data.len() > PCRE_MAX_SCAN_BYTES {
            &ctx.data[..PCRE_MAX_SCAN_BYTES]
        } else {
            ctx.data
        };
        for (i, subsig) in subsigs.iter().enumerate() {
            match subsig {
                Subsignature::Pcre(pcre) => {
                    if pcre.trigger.eval(counts).matched {
                        // Compile the regex on first trigger (lazy — most PCREs
                        // never fire, so they stay uncompiled and cost no RAM).
                        if let Some(re) = pcre.regex.get() {
                            counts[i] = if pcre.global {
                                if pcre_count_limit == usize::MAX {
                                    re.find_iter(pcre_needle).count()
                                } else {
                                    re.find_iter(pcre_needle).take(pcre_count_limit).count()
                                }
                            } else {
                                usize::from(pcre.regex.is_match(pcre_needle))
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

        #[cfg(target_os = "android")]
        let t_after_p2 = std::time::Instant::now();
        #[cfg(target_os = "android")]
        let debug_p2_us = t_after_p2.duration_since(t_after_fuzzy).as_micros();

        let eval_matched = signature.expression.eval(counts).matched;
        #[cfg(target_os = "android")]
        let debug_eval_us = std::time::Instant::now().duration_since(t_after_p2).as_micros();

        #[cfg(target_os = "android")]
        let debug_total_us = std::time::Instant::now().duration_since(t_debug).as_micros();
        #[cfg(target_os = "android")]
        if debug_total_us >= 20_000 {
            rust_timing_log!(
                "[SCAN-DEBUG] {} gate={}us p1_body={}us fuzzy={}us p2_pcre_bc={}us eval={}us total={}us subsig_sum={}us",
                signature.name,
                debug_gate_us,
                debug_p1_us,
                debug_fuzzy_us,
                debug_p2_us,
                debug_eval_us,
                debug_total_us,
                bufs.detail.iter().map(|d| d.elapsed_us).sum::<u128>(),
            );
        }

        if eval_matched {
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
                    });
                }
                return;
            }
            matches.push(ScanMatch {
                name: signature.name.to_string(),
                kind: SignatureKind::Logical,
                source: signature.source.clone(),
                object_path: ctx.object_path.to_string(),
                view: ctx.view,
            });
        }
    }

    /// Run a ClamBC program for a matched trigger, building its context from the
    /// scan (file buffer, trigger subsig match counts). Returns the
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
        match bc.run(&mut bctx) {
            Ok(_) => bctx.virname,
            Err(_) => None,
        }
    }
}

/// ClamAV target codes worth running the ClamAV engine on at all: HTML(3),
/// Graphics(5), ELF(6), ASCII text(7), PDF(10), SWF(11), DEX(16), APK(17),
/// generic ZIP(18).
/// Anything else — a confidently-typed desktop-only format or a type we can't
/// classify — never runs on Android, so `scan_object` skips the whole engine
/// for it rather than relying on `target_matches` to reject each candidate.
const CLAMAV_ALLOWED_TARGETS: [u32; 9] = [3, 5, 6, 7, 10, 11, 16, 17, 18];

fn clamav_target_allowed(target: Option<u32>) -> bool {
    target.map_or(false, |t| CLAMAV_ALLOWED_TARGETS.contains(&t))
}

fn target_matches(target: Option<u32>, ctx: &ScanContext<'_>, sig_name: &str) -> bool {
    let want = target.unwrap_or(0);

    // Target 0 = generic: applies to every file type.
    if want == 0 {
        // Andr.* signatures: only match ELF(6), text(7), DEX(16), APK(17).
        if sig_name.starts_with("Andr.") {
            let detected = ctx.detected_target
                .or_else(|| detect_builtin_target(ctx))
                .unwrap_or(0);
            return matches!(detected, 6 | 7 | 16 | 17);
        }
        return true;
    }
    // Prefer the precise `.ftm`-derived type when available (strict typing).
    if let Some(detected) = ctx.detected_target {
        return want == detected;
    }
    // Concrete magic-based typing. ClamAV always types the file and only runs a
    // signature whose Target matches; without this, a type-specific signature
    // (e.g. a SWF `Target:11` exploit rule) fires on unrelated files (an APK
    // that merely contains the same strings) — a real false positive. So if the
    // file is a KNOWN type different from the signature's target, reject it. This
    // gate applies even in non-strict mode; it only rejects clear cross-type
    // mismatches, never an indeterminate type (which stays permissive to avoid
    // false negatives).
    if let Some(detected) = detect_builtin_target(ctx) {
        return want == detected;
    }
    match want {
        3 => looks_like_html(ctx.data),
        7 => looks_like_ascii_text(ctx.data),
        _ => false,
    }
}

/// Detect whether a ZIP buffer is an Android APK by looking for the
/// `AndroidManifest.xml` entry in the first/last 1 MB (where ZIP local file
/// headers and central directory appear).
pub fn is_apk_zip(data: &[u8]) -> bool {
    let scan_size = 1 << 20;
    let head_end = data.len().min(scan_size);
    let tail_start = data.len().saturating_sub(scan_size);
    let head = &data[..head_end];
    let tail = &data[tail_start..];

    let has = |region: &[u8], pat: &[u8]| region.windows(pat.len()).any(|w| w == pat);

    let has_dex = |region: &[u8]| {
        if has(region, b"classes.dex") {
            return true;
        }
        for w in region.windows(8) {
            if w.starts_with(b"classes") && w[7].is_ascii_digit() {
                return true;
            }
        }
        false
    };

    let has_lib_so = |region: &[u8]| {
        let mut i = 0;
        while let Some(pos) = region[i..].windows(3).position(|w| w == b".so") {
            let p = i + pos;
            if p >= 4 && region[p - 4..p] == [b'l', b'i', b'b', b'/'] {
                return true;
            }
            i = p + 1;
        }
        false
    };

    let has_apk_content = |region: &[u8]| has_dex(region) || has_lib_so(region);

    let manifest_in_head = head_end > 0 && has(head, b"AndroidManifest.xml");
    let manifest_in_tail = tail_start > 0 && has(tail, b"AndroidManifest.xml");

    (manifest_in_head && (has_apk_content(head) || has_apk_content(tail)))
        || (manifest_in_tail && (has_apk_content(head) || has_apk_content(tail)))
}

/// Best-effort concrete file-type detection by magic → ClamAV target number.
/// Returns `Some` only for confident detections (so callers reject clear
/// cross-type mismatches); `None` when indeterminate (callers stay permissive).
fn detect_builtin_target(ctx: &ScanContext<'_>) -> Option<u32> {
    let d = ctx.data;
    if d.starts_with(b"\x7fELF") {
        return Some(6); // CL_TYPE_ELF
    }
    if d.starts_with(b"%PDF") {
        return Some(10); // CL_TYPE_PDF
    }
    if d.starts_with(b"GIF8")
        || d.starts_with(&[0x89, b'P', b'N', b'G'])
        || d.starts_with(&[0xff, 0xd8, 0xff])
    {
        return Some(5); // CL_TYPE_GRAPHICS
    }
    if d.len() >= 4 && d[..4] == [0x64, 0x65, 0x78, 0x0a] {
        return Some(16); // CL_TYPE_DEX
    }
    if d.len() >= 4 && d[..2] == [0x50, 0x4b] && d[2] == 0x03 && d[3] == 0x04 {
        if is_apk_zip(d) {
            return Some(17); // CL_TYPE_APK
        }
        return Some(18); // CL_TYPE_ZIP (generic ZIP, not APK)
    }
    // SWF: `FWS` (uncompressed), `CWS` (zlib), or `ZWS` (lzma) + version byte.
    if d.len() >= 3
        && (d[0] == b'F' || d[0] == b'C' || d[0] == b'Z')
        && d[1] == b'W'
        && d[2] == b'S'
    {
        return Some(11); // CL_TYPE_SWF
    }
    // Heuristic-based detection (no fixed magic) for format-agnostic types
    // that ClamAV signatures legitimately target.  The same heuristics are
    // also used in `target_matches` as a per-signature fallback — adding them
    // here too ensures the pre‑gate type check identifies these files as
    // supported so the engine actually runs on them.
    if looks_like_html(d) {
        return Some(3); // CL_TYPE_HTML
    }
    if looks_like_ascii_text(d) {
        return Some(7); // CL_TYPE_ASCII_TEXT
    }
    None
}

fn clamav_type_to_target(clamav_type: &str) -> Option<u32> {
    // No PE (CL_TYPE_MSEXE) or OLE2/MSOLE2 arms here: neither Windows PE
    // executables nor legacy MS Office/OLE2 documents are Android-relevant
    // formats — target 1 (PE) isn't produced by this function and target 2
    // (OLE2) isn't in `CLAMAV_ALLOWED_TARGETS`, so mapping to either would
    // just be dead weight that never reaches the scan path.
    Some(match clamav_type {
        "CL_TYPE_HTML" => 3,
        "CL_TYPE_GRAPHICS" | "CL_TYPE_GIF" | "CL_TYPE_PNG" | "CL_TYPE_JPEG" => 5,
        "CL_TYPE_ELF" => 6,
        "CL_TYPE_TEXT_ASCII" => 7,
        "CL_TYPE_PDF" => 10,
        "CL_TYPE_SWF" => 11,
        "CL_TYPE_ZIP" => 18,
        "CL_TYPE_APK" => 17,
        "CL_TYPE_DEX" => 16,
        _ => return None,
    })
}

/// Whether the first 256 bytes look like human-readable text (ASCII or UTF-8).
pub fn is_text_like(data: &[u8]) -> bool {
    let sample = if data.len() > 256 { &data[..256] } else { data };
    let mut text_bytes: usize = 0;
    let mut i = 0;
    while i < sample.len() {
        let b = sample[i];
        if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            text_bytes += 1;
            i += 1;
        } else if b >= 0x80 {
            let rem = sample.len() - i;
            if b & 0xE0 == 0xC0 && rem >= 2 && sample[i + 1] & 0xC0 == 0x80 {
                text_bytes += 2; i += 2;
            } else if b & 0xF0 == 0xE0 && rem >= 3 && sample[i + 1] & 0xC0 == 0x80 && sample[i + 2] & 0xC0 == 0x80 {
                text_bytes += 3; i += 3;
            } else if b & 0xF8 == 0xF0 && rem >= 4
                && sample[i + 1] & 0xC0 == 0x80
                && sample[i + 2] & 0xC0 == 0x80
                && sample[i + 3] & 0xC0 == 0x80
            {
                text_bytes += 4; i += 4;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    text_bytes > sample.len() * 9 / 10
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

fn is_unsupported_archive(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] // RAR v5
    || data.len() >= 7 && data[..7] == [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] // RAR v1.5
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        ContainerSignature, ContainerType, ExtendedSignature, FileTypeMagic, NumSpec, OffsetSpec,
        SourceLocation,
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };

        // Atom present → detected.
        let hit = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].name, "Test.Signature");

        // Atom absent → correctly skipped, no match.
        let miss = engine.scan_bytes(b"xxxyyyzzz", ScanOptions::default());
        assert!(miss.is_empty());
    }

    #[test]
    fn scans_extracted_zip_child() {
        // Extraction lives in `hydradragonandroid`'s `collect_buffers`, which
        // hands each extracted member to `scan_bytes_named` as its own whole
        // buffer with the member's `object_path`. This test mirrors that
        // contract directly: scan the extracted child bytes with the path the
        // caller assigns, and assert the match carries it through.
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
        let found = engine.scan_bytes_named(b"MALWARE", "root#archive[0]", ScanOptions::default(), &[]);
        assert!(found.iter().any(|hit| {
            hit.name == "Test.Zip.Child"
                && hit.object_path == "root#archive[0]"
                && hit.view == ScanView::Raw
        }));
    }

    #[test]
    fn scans_pcre_logical_signature() {
        let (sig, warnings) = crate::logical::parse_logical_signature(
            "Test.Pcre;Target:0;0&1;414141;0/world/",
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
        // Body "AAA" present and regex "world" present -> match.
        let found = engine.scan_bytes(b"AAA hello world", ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Pcre"));
        // Body trigger "AAA" absent -> PCRE not evaluated -> no match.
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
        // "SIZE" then 2 LE bytes = 5 (>0) -> match.
        // Pad to 260+ bytes so first-256 sample stays 99% text (>90% for gate).
        let mut data = vec![b'X'; 260];
        data[..4].copy_from_slice(b"SIZE");
        data[4] = 5; data[5] = 0;
        data[6..10].copy_from_slice(b"tail");
        let found = engine.scan_bytes(&data, ScanOptions::default());
        assert!(found.iter().any(|m| m.name == "Test.Bc"));
        // 2 LE bytes = 0 -> byte-compare fails.
        data[4] = 0; data[5] = 0;
        let none = engine.scan_bytes(&data, ScanOptions::default());
        assert!(none.is_empty());
    }

    #[test]
    fn scans_container_metadata_signature() {
        let container = ContainerSignature {
            name: "Test.Cdb".into(),
            container_type: ContainerType::Format("zip"),
            container_size: NumSpec::Any,
            has_filename: true,
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
        // Container signatures match extracted children.
        // Drive the extraction-layer path directly via scan_object.
        let mut state = ScanState { matches: Vec::new() };
        engine.scan_object(
            b"MALWARE",
            "root#archive[0]",
            Some("zip"),
            Some(7),
            Some(1),
            Some("child.bin".into()),
            1,
            ScanOptions::default(),
            &[],
            &mut state,
            &mut None,
            false,
            false,
        );
        assert!(state
            .matches
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
            patterns: compile_pattern_variants("52494646", Modifiers::default()).unwrap().into(),
            clamav_type: "CL_TYPE_RIFF".into(),
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };
        // "RIFFAB": .ftm types it as a RIFF container (no target mapping, so
        // detected_target stays None); the sig's target 3 (HTML) still gets
        // filtered — either the .ftm type maps to a non-3 target, or (as here)
        // the `detect_builtin_target`/text-heuristic fallback in `target_matches`
        // rejects the mismatch. Confirms strict typing filters unrelated targets
        // without relying on any PE/Windows-executable-specific type.
        assert!(engine.scan_bytes(b"RIFFAB", ScanOptions::default()).is_empty());
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

    fn scan_bytes_naive(db: &Database, data: &[u8]) -> Vec<String> {
        use crate::database::OffsetSpec;
        let mut matches = Vec::new();
        let ctx = ScanContext {
            data,
            detected_target: None,
            view: ScanView::Raw,
            object_path: "root",
            container_type: None,
            container_size_real: None,
            container_file_pos: None,
            container_entry_name: None,
            image_fuzzy_hash: std::cell::OnceCell::new(),
        };
        // Naive extended scan
        for (_si, sig) in db.extended.iter().enumerate() {
            let ranges = sig.offset.scan_ranges(data.len());
            if ranges.is_empty() { continue; }
            let mut matched = false;
            for pattern in &sig.patterns {
                if !pattern.find_all(data, &ranges, 1).is_empty() {
                    matched = true;
                    break;
                }
            }
            if matched {
                matches.push(db.ext_name(sig).to_string());
            }
        }
        // Naive logical scan
        for sig in &db.logical {
            let n = sig.subsignatures.len();
            let mut counts = vec![0; n];
            let mut last_offsets = vec![None; n];
            // Evaluate body subsignatures
            for (i, sub) in sig.subsignatures.iter().enumerate() {
                if let Subsignature::Body { offset, patterns } = sub {
                    let any = OffsetSpec::any();
                    let offset = offset.as_deref().unwrap_or(&any);
                    let ranges = offset.scan_ranges(data.len());
                    if !ranges.is_empty() {
                        let mut count = 0;
                        let mut last_end = None;
                        for pattern in patterns {
                            let hits = pattern.find_all(data, &ranges, usize::MAX);
                            count += hits.len();
                            if let Some(m) = hits.last() {
                                last_end = Some(m.end.max(last_end.unwrap_or(0)));
                            }
                        }
                        counts[i] = count;
                        last_offsets[i] = last_end;
                    }
                }
            }
            // Fuzzy subsignatures
            for (i, sub) in sig.subsignatures.iter().enumerate() {
                if let Subsignature::Fuzzy(hash) = sub {
                    if ctx.image_fuzzy_hash() == Some(*hash) {
                        counts[i] = 1;
                    }
                }
            }
            // PCRE and ByteCompare
            for (i, sub) in sig.subsignatures.iter().enumerate() {
                match sub {
                    Subsignature::Pcre(pcre) => {
                        if pcre.trigger.eval(&counts).matched {
                            if let Some(re) = pcre.regex.get() {
                                counts[i] = if pcre.global {
                                    re.find_iter(data).count()
                                } else {
                                    usize::from(re.is_match(data))
                                };
                            }
                        }
                    }
                    Subsignature::ByteCompare(spec) => {
                        let trigger_hit = counts.get(spec.trigger_subsig).copied().unwrap_or(0) > 0;
                        if trigger_hit {
                            let base = last_offsets.get(spec.trigger_subsig).copied().flatten().unwrap_or(0);
                            if spec.evaluate(data, base) {
                                counts[i] = 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
            if sig.expression.eval(&counts).matched {
                matches.push(sig.name.to_string());
            }
        }
        let mut v: Vec<String> = matches.into_iter().map(|name| format!("{}@root", name)).collect();
        v.sort();
        v.dedup();
        v
    }

    fn assert_threading_equiv(build_db: impl Fn() -> Database, data: &[u8]) -> Vec<String> {
        let opts = ScanOptions::default();
        let db = build_db();
        // Naive scan (ground truth)
        let naive = scan_bytes_naive(&db, data);
        // AtomFilterDb scan
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&db);
        let engine = Engine {
            database: db,
            atomfilter_db,
            yara: Vec::new(),
        };
        let filter_matches = match_keys(&engine.scan_bytes(data, opts));
        assert_eq!(
            naive, filter_matches,
            "AtomFilterDb scan differed from naive scan on {:?}",
            String::from_utf8_lossy(data)
        );
        filter_matches
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
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        (
            Engine {
                database,
                atomfilter_db,
                yara: Vec::new(),
            },
            warnings,
        )
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
        // Container extraction is done by `collect_buffers` before reaching
        // the engine; it tags each extracted child with its parent's
        // `CL_TYPE_*` via `scan_object`'s `container_type` argument. Drive that
        // path directly: scan the child bytes with `container_type = ZIP` and
        // confirm the `Container:CL_TYPE_ZIP` TDB gate lets the body match fire.
        let mut state = ScanState { matches: Vec::new() };
        engine.scan_object(
            b"xxMALWAREyy",
            "root#archive[0]",
            Some("CL_TYPE_ZIP"),
            None,
            None,
            None,
            1,
            ScanOptions::default(),
            &[],
            &mut state,
            &mut None,
            false,
            false,
        );
        assert!(state.matches.iter().any(|m| m.name == "Test.InZip"));
    }

    #[test]
    fn swf_target_signature_matches_swf() {
        // A Target:11 (SWF) signature matches actual SWF content.
        let (engine, _) = engine_with_logical(
            "Test.Swf;Engine:81-255,Target:11;(0&1);5669727475616c50726f74656374::i;4b65726e656c3332::i",
        );
        // SWF with both strings present → match.
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
    fn tdb_icongroup_never_matches_without_pe() {
        // IconGroup was PE-specific; without PE detection it never matches.
        // No unsupported-TDB warning is produced.
        let (engine, warnings) =
            engine_with_logical("Test.Icon;Engine:1-255,IconGroup1:BROWSER,Target:0;0;4142");
        assert!(
            warnings.is_empty(),
            "IconGroup parsed normally; no unsupported-TDB warning"
        );
        assert!(engine.scan_bytes(b"xxAByy", ScanOptions::default()).is_empty());
    }

    #[test]
    fn is_unsupported_archive_detects_rar5() {
        assert!(is_unsupported_archive(&[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]));
    }

    #[test]
    fn is_unsupported_archive_detects_rar15() {
        assert!(is_unsupported_archive(&[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]));
    }

    #[test]
    fn is_unsupported_archive_rejects_zip_and_short() {
        assert!(!is_unsupported_archive(&[0x50, 0x4b, 0x03, 0x04]));
        assert!(!is_unsupported_archive(&[0x52]));
    }

    #[test]
    fn scan_options_default_scan_archive_true() {
        assert!(ScanOptions::default().scan_archives);
        assert_eq!(ScanOptions::default().max_recursion, 16);
        assert_eq!(ScanOptions::default().max_child_size, 650 * 1024 * 1024);
    }

    #[test]
    fn scan_options_disabled_archive_skips_extraction() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.NoArchive"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };

        let opts = ScanOptions { scan_archives: false, ..ScanOptions::default() };
        let found = engine.scan_bytes(b"xxABCyy", opts);
        assert_eq!(found.len(), 1, "scan_archives=false must still scan raw bytes");
    }

    #[test]
    fn extended_signature_nocase_matches_any_case() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let nocase = Modifiers { nocase: true, ..Modifiers::default() };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.NocaseExt"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("616263", nocase).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };

        // All these should match "abc" (case-insensitively)
        assert!(engine.scan_bytes(b"ABC!", ScanOptions::default()).iter().any(|m| m.name == "Test.NocaseExt"));
        assert!(engine.scan_bytes(b"abc!", ScanOptions::default()).iter().any(|m| m.name == "Test.NocaseExt"));
        assert!(engine.scan_bytes(b"AbC!", ScanOptions::default()).iter().any(|m| m.name == "Test.NocaseExt"));

        // Should not match when completely absent
        assert!(engine.scan_bytes(b"xyz!", ScanOptions::default()).is_empty());
    }

    #[test]
    fn multiple_extended_signatures_all_match() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let database = Database {
            extended: vec![
                ExtendedSignature {
                    name: crate::database::intern_name(&mut name_arena, "Sig.Alpha"),
                    target: Some(0),
                    offset: OffsetSpec::any(),
                    patterns: compile_pattern_variants("414141", Modifiers::default()).unwrap().into(),
                    source: source.clone(),
                },
                ExtendedSignature {
                    name: crate::database::intern_name(&mut name_arena, "Sig.Beta"),
                    target: Some(0),
                    offset: OffsetSpec::any(),
                    patterns: compile_pattern_variants("424242", Modifiers::default()).unwrap().into(),
                    source: source.clone(),
                },
                ExtendedSignature {
                    name: crate::database::intern_name(&mut name_arena, "Sig.Gamma"),
                    target: Some(0),
                    offset: OffsetSpec::any(),
                    patterns: compile_pattern_variants("434343", Modifiers::default()).unwrap().into(),
                    source,
                },
            ],
            name_arena,
            ..Default::default()
        };
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };

        let found = engine.scan_bytes(b"AAABBBCCC", ScanOptions::default());
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|m| m.name == "Sig.Alpha"));
        assert!(found.iter().any(|m| m.name == "Sig.Beta"));
        assert!(found.iter().any(|m| m.name == "Sig.Gamma"));
    }

    #[test]
    fn scans_eicar_test_signature() {
        let source = SourceLocation {
            path: std::sync::Arc::from(std::path::Path::new("test.ndb")),
            line: 1,
        };
        let mut name_arena = String::new();
        let hex = "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a";
        let database = Database {
            extended: vec![ExtendedSignature {
                name: crate::database::intern_name(&mut name_arena, "Test.Eicar"),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants(hex, Modifiers::default()).unwrap().into(),
                source,
            }],
            name_arena,
            ..Default::default()
        };
        let atomfilter_db = crate::atomfilter_build::AtomFilterBuilder::build(&database);
        let engine = Engine { database, atomfilter_db, yara: Vec::new() };

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let hit = engine.scan_bytes(eicar, ScanOptions::default());
        assert_eq!(hit.len(), 1, "EICAR test signature should detect the EICAR string");
        assert_eq!(hit[0].name, "Test.Eicar");

        // Should not match on a benign string
        let miss = engine.scan_bytes(b"hello world this is not malware", ScanOptions::default());
        assert!(miss.is_empty(), "EICAR signature must not fire on benign content");
    }

}
