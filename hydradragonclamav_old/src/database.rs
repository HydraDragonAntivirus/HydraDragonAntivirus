use crate::logical::{parse_logical_signature, LogicalSignature};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use crate::pe::PeInfo;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

/// A name stored in [`Database::name_arena`] as a `(start, len)` byte range. 8 bytes
/// inline vs a 16-byte `Box<str>` + its own heap allocation — for ~600k extended
/// signatures this removes ~600k small allocations (the bulk of the loader's
/// allocator overhead) and shrinks each signature struct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NameSpan {
    pub start: u32,
    pub len: u32,
}

/// Append `name` to the arena and return its span. Names total well under 4 GiB.
pub fn intern_name(arena: &mut String, name: &str) -> NameSpan {
    let start = arena.len() as u32;
    arena.push_str(name);
    NameSpan { start, len: name.len() as u32 }
}

#[derive(Debug, Default)]
pub struct Database {
    pub extended: Vec<ExtendedSignature>,
    pub logical: Vec<LogicalSignature>,
    pub container: Vec<ContainerSignature>,
    pub file_type_magic: Vec<FileTypeMagic>,
    /// Phishing URL databases (`.pdb`/`.gdb` protected domains, `.wdb` allow list).
    pub phishing: crate::phishing::PhishingDb,
    /// Icon signatures (`.idb`) — fingerprints loaded and matched against PE icons
    /// by `icon_match` (evaluates `IconGroup1/2` TDB constraints).
    pub icons: crate::icon::IconMatcher,
    /// Certificate trust/block rules (`.crb`) — records loaded; Authenticode
    /// verification is a follow-up.
    pub certs: crate::cert::CertTrustDb,
    pub unsupported: Vec<UnsupportedRecord>,
    /// Decoded + interpreter-prepared ClamBC programs. A logical signature whose
    /// `bytecode` field is `Some(i)` is a bytecode trigger that runs `[i]`.
    pub bytecode_programs: Vec<crate::bytecode_vm::Bc>,
    /// Backing storage for every [`ExtendedSignature`] name (one contiguous buffer
    /// instead of one heap allocation per name). Resolve a span via [`Self::ext_name`].
    pub name_arena: String,
}

impl Database {
    /// Resolve an extended signature's interned name back to a `&str`.
    #[inline]
    pub fn ext_name(&self, sig: &ExtendedSignature) -> &str {
        let s = sig.name.start as usize;
        &self.name_arena[s..s + sig.name.len as usize]
    }

    /// Aggregate pattern memory across every signature, for `--mem-stats`.
    pub fn pattern_mem_stats(&self) -> crate::pattern::MemStats {
        let mut s = crate::pattern::MemStats::default();
        for sig in &self.extended {
            for p in sig.patterns.iter() {
                let ps = p.mem_stats();
                s.add(&ps);
            }
        }
        for sig in &self.file_type_magic {
            for p in sig.patterns.iter() {
                let ps = p.mem_stats();
                s.add(&ps);
            }
        }
        for sig in &self.logical {
            for sub in &sig.subsignatures {
                if let crate::logical::Subsignature::Body { patterns, .. } = sub {
                    for p in patterns.iter() {
                        let ps = p.mem_stats();
                        s.add(&ps);
                    }
                }
            }
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedSignature {
    /// Interned into [`Database::name_arena`]; resolve with [`Database::ext_name`].
    pub name: NameSpan,
    pub target: Option<u32>,
    pub offset: OffsetSpec,
    pub patterns: Box<[Pattern]>,
    pub source: SourceLocation,
}

/// Container metadata (`.cdb`) signature.
///
/// Only the fields HydraDragon can observe from `hydradragonextractor` are
/// matched: container type/size, member real size, and member position. Fields
/// that need archive member metadata we don't expose (`filename`, `encrypted`,
/// compressed `size_in_container`, CRC) are parsed but cause the signature to be
/// skipped when constrained, so it never false-positives on unknowable data.
#[derive(Clone, Debug)]
pub struct ContainerSignature {
    pub name: Box<str>,
    pub container_type: ContainerType,
    pub container_size: NumSpec,
    /// True when the signature constrains the archive member filename.
    /// We can't observe filenames inside archives, so any such sig is skipped
    /// at scan time. Stored as a bool — no need to compile and hold the Regex.
    pub has_filename: bool,
    pub size_in_container: NumSpec,
    pub size_real: NumSpec,
    pub encrypted: Option<bool>,
    pub file_pos: NumSpec,
    pub source: SourceLocation,
}

/// Resolved container type for a `.cdb` signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContainerType {
    /// `*` — any container.
    Any,
    /// A container format `hydradragonextractor` can detect, e.g. `"zip"`.
    Format(&'static str),
    /// A ClamAV container type HydraDragon cannot detect/extract (never matches).
    Unsupported,
}

/// A numeric field constraint: `*`, exact, or a `x-y` / `x-` / `-y` range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumSpec {
    Any,
    Exact(u64),
    Range(Option<u64>, Option<u64>),
}

/// File-type magic (`.ftm`) record (magictype 0 absolute / 1 body-pattern).
#[derive(Clone, Debug)]
pub struct FileTypeMagic {
    pub offset: OffsetSpec,
    pub patterns: Box<[Pattern]>,
    pub clamav_type: Box<str>,
    pub source: SourceLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    /// Shared so all signatures from one database file point at a single path
    /// allocation instead of ~500k duplicate `PathBuf`s.
    pub path: Arc<Path>,
    pub line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedRecord {
    pub source: SourceLocation,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadError {
    pub source: SourceLocation,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct LoadReport {
    pub files_seen: usize,
    pub lines_seen: usize,
    pub extended_loaded: usize,
    /// Old-format `.db` (`name=hexsig`) body signatures loaded. These are stored
    /// in `database.extended` and scan through the same path; counted separately
    /// only so the report can show they're no longer being silently dropped.
    pub db_loaded: usize,
    pub logical_loaded: usize,
    pub container_loaded: usize,
    pub ftm_loaded: usize,
    pub hash_files_skipped: usize,
    pub unsupported_files: usize,
    pub unsupported_records: usize,
    pub bytecodes_loaded: usize,
    /// Signature names collected from `.ign`/`.ign2` ignore lists.
    pub ign_entries: usize,
    /// Signatures skipped because their name is in the ignore set.
    pub ignored_skipped: usize,
    /// Logical signatures skipped because they carry an unrecognised TDB attribute
    /// (typically a typo'd key). ClamAV's `init_tdb` returns `CL_BREAK` and skips
    /// these too — not a detection gap, so tracked separately from parse errors.
    pub tdb_attr_skipped: usize,
    // Per-category file counts for the not-yet-matched / non-detection extensions,
    // so every file in `files_seen` is accounted for (no silent drops). Each of
    // these also pushes one `UnsupportedRecord` naming the exact disposition.
    /// `.pdb`/`.gdb`/`.wdb` — phishing URL/domain database files seen.
    pub phishing_files: usize,
    /// Phishing entries loaded across all `.pdb`/`.gdb`/`.wdb` files.
    pub phishing_loaded: usize,
    /// `.idb` — icon fuzzy-image signature files seen.
    pub icon_files: usize,
    /// Icon fingerprints loaded across all `.idb` files.
    pub icon_loaded: usize,
    /// `.crb`/`.cat` — Authenticode certificate trust/block files seen.
    pub cert_files: usize,
    /// `.crb` certificate records loaded.
    pub cert_loaded: usize,
    /// `.ioc` — OpenIOC XML indicator databases.
    pub ioc_files: usize,
    /// `.cfg` — dconf engine configuration (not detection).
    pub config_files: usize,
    /// `.info`/`.dat`/`.pwdb`/`.sign` — container metadata / archive passwords.
    pub metadata_files: usize,
    /// `.cvd`/`.cld`/`.cud` — signed signature containers (handled by the bytecode
    /// / CVD loader, not the per-line database loader).
    pub container_db_files: usize,
    /// `.zmd`/`.rmd` — deprecated ClamAV metadata formats.
    pub deprecated_files: usize,
    /// Any extension not recognised by ClamAV's dispatch table.
    pub unknown_files: usize,
    pub by_extension: BTreeMap<String, usize>,
    pub errors: Vec<LoadError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffsetSpec {
    pub anchor: OffsetAnchor,
    pub max_shift: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OffsetAnchor {
    Any,
    Absolute(usize),
    EofMinus(usize),
    EntryPoint(i64),
    SectionStart { index: usize, delta: i64 },
    SectionEntire { index: usize },
    LastSectionStart { delta: i64 },
    VersionInfo,
    MacroGroup(String),
    Unsupported(String),
}

impl Database {
    pub fn load_dir(path: impl AsRef<Path>) -> io::Result<(Self, LoadReport)> {
        let mut database = Database::default();
        let mut report = LoadReport::default();
        // First pass: collect signature names to ignore from .ign/.ign2 files
        // (ClamAV engine->ignored), so the second pass can skip them. Must
        // precede signature loading regardless of directory order.
        let ignored = collect_ignored(path.as_ref(), &mut report)?;
        visit_database_dir(path.as_ref(), &mut |file| {
            load_file(file, &mut database, &mut report, &ignored)
        })?;
        // Drop the over-allocated capacity the push-loops left behind (a `Vec`
        // grows geometrically, so the last doubling can waste up to ~2x). On
        // half a million signatures that slack is real resident memory.
        database.extended.shrink_to_fit();
        database.logical.shrink_to_fit();
        database.container.shrink_to_fit();
        database.file_type_magic.shrink_to_fit();
        Ok((database, report))
    }
}

impl OffsetSpec {
    pub fn any() -> Self {
        Self {
            anchor: OffsetAnchor::Any,
            max_shift: None,
        }
    }

    pub fn parse(raw: &str) -> Self {
        let (base, max_shift) = match raw.split_once(',') {
            Some((base, shift)) => (base, shift.parse::<usize>().ok()),
            None => (raw, None),
        };

        let upper = base.to_ascii_uppercase();
        let anchor = if base == "*" {
            OffsetAnchor::Any
        } else if let Some(rest) = upper.strip_prefix("EOF-") {
            rest.parse::<usize>()
                .map(OffsetAnchor::EofMinus)
                .unwrap_or_else(|_| OffsetAnchor::Unsupported(base.to_string()))
        } else if upper == "EP" {
            OffsetAnchor::EntryPoint(0)
        } else if let Some(rest) = upper.strip_prefix("EP+") {
            parse_i64(rest)
                .map(OffsetAnchor::EntryPoint)
                .unwrap_or_else(|| OffsetAnchor::Unsupported(base.to_string()))
        } else if let Some(rest) = upper.strip_prefix("EP-") {
            parse_i64(rest)
                .map(|value| OffsetAnchor::EntryPoint(-value))
                .unwrap_or_else(|| OffsetAnchor::Unsupported(base.to_string()))
        } else if let Some(rest) = upper.strip_prefix("SE") {
            rest.parse::<usize>()
                .map(|index| OffsetAnchor::SectionEntire { index })
                .unwrap_or_else(|_| OffsetAnchor::Unsupported(base.to_string()))
        } else if upper == "SL" {
            OffsetAnchor::LastSectionStart { delta: 0 }
        } else if let Some(rest) = upper.strip_prefix("SL+") {
            parse_i64(rest)
                .map(|delta| OffsetAnchor::LastSectionStart { delta })
                .unwrap_or_else(|| OffsetAnchor::Unsupported(base.to_string()))
        } else if let Some(rest) = upper.strip_prefix("SL-") {
            parse_i64(rest)
                .map(|delta| OffsetAnchor::LastSectionStart { delta: -delta })
                .unwrap_or_else(|| OffsetAnchor::Unsupported(base.to_string()))
        } else if upper.starts_with('S') && upper.len() > 1 {
            parse_section_start(base).unwrap_or_else(|| OffsetAnchor::Unsupported(base.to_string()))
        } else if upper == "VI" {
            OffsetAnchor::VersionInfo
        } else if base.starts_with('$') {
            OffsetAnchor::MacroGroup(base.trim_start_matches('$').to_string())
        } else {
            base.parse::<usize>()
                .map(OffsetAnchor::Absolute)
                .unwrap_or_else(|_| OffsetAnchor::Unsupported(base.to_string()))
        };

        Self { anchor, max_shift }
    }

    pub fn scan_ranges(&self, data_len: usize, pe: Option<&PeInfo>) -> Vec<(usize, usize)> {
        match &self.anchor {
            OffsetAnchor::Any => vec![(0, data_len)],
            OffsetAnchor::Absolute(offset) => shifted_range(*offset, data_len, self.max_shift),
            OffsetAnchor::EofMinus(back) => data_len
                .checked_sub(*back)
                .map(|offset| shifted_range(offset, data_len, self.max_shift))
                .unwrap_or_default(),
            OffsetAnchor::EntryPoint(delta) => pe
                .and_then(|info| info.entry_point_offset)
                .and_then(|offset| apply_delta(offset, *delta))
                .map(|offset| shifted_range(offset, data_len, self.max_shift))
                .unwrap_or_default(),
            OffsetAnchor::SectionStart { index, delta } => pe
                .and_then(|info| info.sections.get(*index))
                .and_then(|section| apply_delta(section.raw_start, *delta))
                .map(|offset| shifted_range(offset, data_len, self.max_shift))
                .unwrap_or_default(),
            OffsetAnchor::SectionEntire { index } => pe
                .and_then(|info| info.sections.get(*index))
                .map(|section| {
                    let start = section.raw_start.min(data_len);
                    let end = section
                        .raw_start
                        .saturating_add(section.raw_size)
                        .min(data_len);
                    vec![(start, end)]
                })
                .unwrap_or_default(),
            OffsetAnchor::LastSectionStart { delta } => pe
                .and_then(|info| info.sections.last())
                .and_then(|section| apply_delta(section.raw_start, *delta))
                .map(|offset| shifted_range(offset, data_len, self.max_shift))
                .unwrap_or_default(),
            OffsetAnchor::VersionInfo
            | OffsetAnchor::MacroGroup(_)
            | OffsetAnchor::Unsupported(_) => Vec::new(),
        }
    }
}

fn load_file(
    path: &Path,
    database: &mut Database,
    report: &mut LoadReport,
    ignored: &HashSet<Box<str>>,
) -> io::Result<()> {
    report.files_seen += 1;
    let ext = extension_key(path);
    *report.by_extension.entry(ext.clone()).or_insert(0) += 1;

    let kind = classify_extension(&ext);
    match kind {
        // Per-line text databases parsed below.
        ExtKind::BodyNdb | ExtKind::BodyOldDb | ExtKind::Logical | ExtKind::Container
        | ExtKind::FileMagic | ExtKind::Phishing | ExtKind::Icon | ExtKind::CertCrb => {}

        // Hash-based databases are matched by hydradragon elsewhere, not here.
        ExtKind::Hash => {
            report.hash_files_skipped += 1;
            return Ok(());
        }

        // .ign/.ign2 were consumed in the first pass (collect_ignored).
        ExtKind::Ignore => return Ok(()),

        // `.cfg` (engine config) and `.info`/`.dat`/`.pwdb`/`.sign` (container
        // metadata / archive passwords) are NOT detection databases — ClamAV
        // produces no detections from them either. They are accounted for in their
        // own buckets and shown in the report, but they are not a detection gap, so
        // they are not counted as "unsupported".
        ExtKind::Config => {
            report.config_files += 1;
            return Ok(());
        }
        ExtKind::Metadata => {
            report.metadata_files += 1;
            return Ok(());
        }

        // Everything else is a real ClamAV detection format we don't yet *match*,
        // but it must still be accounted for — count it by category and record a
        // precise disposition so `--list-unsupported` names exactly what was
        // deferred and the report sums to 100% of files_seen.
        ExtKind::CertCat
        | ExtKind::Ioc
        | ExtKind::ContainerDb
        | ExtKind::Deprecated
        | ExtKind::Unknown => {
            match kind {
                ExtKind::CertCat => report.cert_files += 1,
                ExtKind::Ioc => report.ioc_files += 1,
                ExtKind::ContainerDb => report.container_db_files += 1,
                ExtKind::Deprecated => report.deprecated_files += 1,
                ExtKind::Unknown => report.unknown_files += 1,
                _ => unreachable!(),
            }
            report.unsupported_files += 1;
            push_unsupported(
                database,
                report,
                SourceLocation {
                    path: Arc::from(path),
                    line: 0,
                },
                kind.disposition(&ext),
            );
            return Ok(());
        }
    }

    if kind == ExtKind::Phishing {
        report.phishing_files += 1;
    }
    if kind == ExtKind::Icon {
        report.icon_files += 1;
    }
    if kind == ExtKind::CertCrb {
        report.cert_files += 1;
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    // One shared path allocation for every signature from this file.
    let src_path: Arc<Path> = Arc::from(path);
    // ClamAV signature databases are NOT guaranteed to be valid UTF-8 — malware
    // names and some fields can carry stray bytes. Read raw bytes per line and
    // decode lossily so a single bad byte never aborts the entire database load
    // (which previously disabled the whole ClamAV engine).
    let mut raw: Vec<u8> = Vec::new();
    let mut line_number = 0usize;
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        line_number += 1;
        let decoded = String::from_utf8_lossy(&raw);
        let line = decoded.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        report.lines_seen += 1;
        let source = SourceLocation {
            path: src_path.clone(),
            line: line_number,
        };
        match kind {
            // `.sdb` parses identically to `.ndb`; ClamAV's `sdb` flag only sets
            // engine->sdb and skips the sigload callback (readdb.c cli_loadndb).
            ExtKind::BodyNdb => match parse_extended_signature(line, source.clone(), &mut database.name_arena) {
                Ok(Some(signature)) if ignored.contains(database.ext_name(&signature)) => {
                    report.ignored_skipped += 1;
                }
                Ok(Some(signature)) => {
                    database.extended.push(signature);
                    report.extended_loaded += 1;
                }
                // Out of f-level range or unsupported target → skip (as ClamAV does).
                Ok(None) => {}
                Err(message) => push_error(report, source, message),
            },
            // Old-format `.db`: `name=hexsig`, generic target, offset `*`
            // (readdb.c cli_loaddb -> cli_add_content_match_pattern on root[0]).
            ExtKind::BodyOldDb => match parse_db_signature(line, source.clone(), &mut database.name_arena) {
                Ok(Some(signature)) if ignored.contains(database.ext_name(&signature)) => {
                    report.ignored_skipped += 1;
                }
                Ok(Some(signature)) => {
                    database.extended.push(signature);
                    report.db_loaded += 1;
                }
                Ok(None) => {}
                Err(message) => push_error(report, source, message),
            },
            ExtKind::Logical => match parse_logical_signature(line, source.clone()) {
                Ok((signature, _)) if ignored.contains(&*signature.name) => {
                    report.ignored_skipped += 1;
                }
                Ok((signature, warnings)) => {
                    for warning in warnings {
                        push_unsupported(database, report, source.clone(), warning);
                    }
                    database.logical.push(signature);
                    report.logical_loaded += 1;
                }
                // An unrecognised TDB attribute is a clean skip (ClamAV CL_BREAK),
                // not a malformed-parse error — count it as such.
                Err(message) if message.starts_with("unrecognised TDB attribute") => {
                    report.tdb_attr_skipped += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            ExtKind::Container => match parse_container_signature(line, source.clone()) {
                Ok(signature) if ignored.contains(&*signature.name) => {
                    report.ignored_skipped += 1;
                }
                Ok(signature) => {
                    database.container.push(signature);
                    report.container_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            ExtKind::FileMagic => match parse_ftm(line, source.clone()) {
                Ok(signature) => {
                    database.file_type_magic.push(signature);
                    report.ftm_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            // Phishing URL databases: `.pdb`/`.gdb` → protected-domain matcher,
            // `.wdb` → allow-list matcher (readdb.c cli_loadpdb / cli_loadwdb).
            ExtKind::Phishing => {
                let result = if ext == "wdb" {
                    database.phishing.allow.add_line(line)
                } else {
                    database.phishing.protected.add_line(line, source.clone())
                };
                match result {
                    Ok(true) => report.phishing_loaded += 1,
                    Ok(false) => {} // intentionally skipped (e.g. `S:` hash entry)
                    Err(message) => push_error(report, source, message),
                }
            }
            // Icon signatures (`.idb`): fingerprint loaded; image matcher is a
            // follow-up (readdb.c cli_loadidb).
            ExtKind::Icon => match database.icons.add_line(line, source.clone()) {
                Ok(()) => report.icon_loaded += 1,
                Err(message) => push_error(report, source, message),
            },
            // Certificate trust/block rules (`.crb`): record loaded; Authenticode
            // verification engine is a follow-up (readdb.c cli_loadcrt).
            ExtKind::CertCrb => {
                let flevel = crate::bytecode_vm::ENGINE_FLEVEL;
                match database.certs.add_line(line, source.clone(), flevel) {
                    Ok(true) => report.cert_loaded += 1,
                    Ok(false) => {} // skipped by functionality-level gating
                    Err(message) => push_error(report, source, message),
                }
            }
            // The non-per-line kinds returned early above before the read loop.
            _ => unreachable!("non-per-line ExtKind reached the parse loop"),
        }
    }
    Ok(())
}

fn parse_container_signature(
    line: &str,
    source: SourceLocation,
) -> Result<ContainerSignature, String> {
    let parts = line.split(':').collect::<Vec<_>>();
    if parts.len() < 8 {
        return Err(
            "container signature needs at least name:type:size:filename:csize:rsize:enc:pos"
                .to_string(),
        );
    }
    Ok(ContainerSignature {
        name: parts[0].into(),
        container_type: cl_type_to_container(parts[1]),
        container_size: NumSpec::parse(parts[2])?,
        has_filename: has_filename_constraint(parts[3]),
        size_in_container: NumSpec::parse(parts[4])?,
        size_real: NumSpec::parse(parts[5])?,
        encrypted: parse_encrypted(parts[6])?,
        file_pos: NumSpec::parse(parts[7])?,
        source,
    })
}

fn parse_ftm(line: &str, source: SourceLocation) -> Result<FileTypeMagic, String> {
    let parts = line.split(':').collect::<Vec<_>>();
    if parts.len() < 6 {
        return Err("ftm needs magictype:offset:magicbytes:name:rtype:type".to_string());
    }
    let offset = match parts[0].trim() {
        // 0 = absolute byte comparison, 1 = body-pattern anywhere, 4 = partition
        // magic (e.g. HFS+/HFSX) — same offset:magic structure, matched as an
        // absolute-offset type signature.
        "0" | "1" | "4" => OffsetSpec::parse(parts[1].trim()),
        other => return Err(format!("unsupported ftm magictype '{other}'")),
    };
    let patterns = compile_pattern_variants(parts[2].trim(), Modifiers::default())
        .map_err(|err| format!("invalid ftm magic bytes: {err}"))?;
    Ok(FileTypeMagic {
        offset,
        patterns: patterns.into_boxed_slice(),
        clamav_type: parts[5].trim().into(),
        source,
    })
}

fn cl_type_to_container(raw: &str) -> ContainerType {
    match raw.trim() {
        "*" => ContainerType::Any,
        "CL_TYPE_ZIP" => ContainerType::Format("zip"),
        "CL_TYPE_GZ" => ContainerType::Format("gz"),
        "CL_TYPE_XZ" => ContainerType::Format("xz"),
        "CL_TYPE_7Z" => ContainerType::Format("7z"),
        "CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR" | "CL_TYPE_TAR" => ContainerType::Format("tar"),
        _ => ContainerType::Unsupported,
    }
}

/// Returns true when the filename field constrains to a specific pattern
/// (i.e. it is not a wildcard). We skip such sigs at scan time since we
/// cannot observe archive member filenames — no need to compile the Regex.
fn has_filename_constraint(raw: &str) -> bool {
    let raw = raw.trim();
    !raw.is_empty() && raw != "*" && raw != ".*"
}

/// Translate a ClamAV / POSIX-ish regex into one Rust's `regex` crate accepts.
/// ClamAV's engine is more permissive; this normalizes the three differences
/// that show up in real signature databases so the patterns compile instead of
/// being dropped, while preserving ClamAV's literal semantics:
///   1. Unknown escapes — `\i` / `\pdf` mean literal `i` / `pdf`. Rust errors on
///      unrecognized escapes, so drop the backslash for those.
///   2. Literal `[` inside a character class — `[[Gg]` means a class containing
///      `[`, `G`, `g`. Rust would read a nested class, so escape it to `\[`.
///   3. Non-quantifier braces — `po{` / `}` are literal `{`/`}` in ClamAV, but
///      Rust treats `{` as a quantifier. Escape braces that aren't a valid
///      `{n}` / `{n,}` / `{n,m}` quantifier.
pub(crate) fn sanitize_clamav_regex(pattern: &str) -> String {
    // Letters that begin a valid Rust-regex escape — keep the backslash for these.
    // `p`/`P` (Unicode property classes) are excluded: ClamAV uses `\p` to mean a
    // literal `p` (e.g. `\pdf` == "pdf").
    const ESCAPE_LETTERS: &str = "aftnrvbBAzdDsSwWx";
    let mut out = String::with_capacity(pattern.len() + 8);
    // Use a peekable iterator — avoids heap-allocating a Vec<char> for every pattern.
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    let mut class_pos = 0usize; // position within the current [...] class

    while let Some(c) = chars.next() {
        // Escapes: keep recognized ones, drop the backslash only from unknown
        // *letter* escapes (e.g. `\i`, `\p`) so they become literals. Keep it for
        // digits (so backreferences like `\1` stay unsupported, not silently
        // turned into a literal digit), punctuation, and recognized escapes.
        if c == '\\' {
            match chars.next() {
                Some(next) => {
                    let drop = next.is_ascii_alphabetic() && !ESCAPE_LETTERS.contains(next);
                    if !drop {
                        out.push('\\');
                    }
                    out.push(next);
                    if in_class {
                        class_pos += 1;
                    }
                }
                None => {
                    out.push('\\'); // trailing backslash — Regex::new will report it
                }
            }
            continue;
        }

        if in_class {
            match c {
                // A literal ']' at the very start of a class (POSIX) needs escaping.
                ']' if class_pos == 0 => {
                    out.push_str("\\]");
                    class_pos += 1;
                }
                ']' => {
                    in_class = false;
                    class_pos = 0;
                    out.push(']');
                }
                // Literal '[' inside a class (but not a POSIX `[:name:]`) — escape
                // so Rust doesn't parse it as a nested class.
                '[' if chars.peek() != Some(&':') => {
                    out.push_str("\\[");
                    class_pos += 1;
                }
                _ => {
                    out.push(c);
                    class_pos += 1;
                }
            }
            continue;
        }

        match c {
            '[' => {
                in_class = true;
                class_pos = 0;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                    class_pos += 1; // '^' occupies position 0; first real char is at 1
                }
            }
            '{' => {
                // Peek at the remaining chars to check for a valid quantifier without
                // collecting the whole tail into a Vec.
                let tail: String = chars.clone().collect();
                if let Some(len) = quantifier_len_str(&tail) {
                    out.push('{');
                    for _ in 0..len {
                        if let Some(ch) = chars.next() {
                            out.push(ch);
                        }
                    }
                } else {
                    out.push_str("\\{"); // not a quantifier — literal brace
                }
            }
            '}' => {
                out.push_str("\\}"); // stray closing brace — literal
            }
            _ => {
                out.push(c);
            }
        }
    }
    out
}

/// If `chars[start]` begins a valid `{n}` / `{n,}` / `{n,m}` quantifier, return
/// its length (including the braces); otherwise `None` (so it's a literal `{`).
/// If `tail` (the string *after* a `{`) begins a valid `n}` / `n,}` / `n,m}`
/// quantifier suffix, return the number of characters to consume from `tail`
/// (not counting the `{` itself); otherwise `None`.
fn quantifier_len_str(tail: &str) -> Option<usize> {
    let mut chars = tail.chars().peekable();
    let mut len = 0usize;
    // Consume leading digits (required).
    let mut saw_digit = false;
    while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
        chars.next();
        len += 1;
        saw_digit = true;
    }
    if !saw_digit {
        return None;
    }
    // Optional `,` followed by optional digits.
    if chars.peek() == Some(&',') {
        chars.next();
        len += 1;
        while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
            chars.next();
            len += 1;
        }
    }
    // Must close with `}`.
    if chars.next() == Some('}') {
        Some(len + 1) // +1 for the closing '}'
    } else {
        None
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_clamav_regex;
    use regex::Regex;

    fn assert_compiles(input: &str) {
        let translated = sanitize_clamav_regex(input);
        Regex::new(&translated)
            .unwrap_or_else(|e| panic!("'{input}' -> '{translated}' failed: {e}"));
    }

    #[test]
    fn translates_clamav_dialect_to_valid_rust_regex() {
        // Unknown escapes become literals.
        assert_eq!(sanitize_clamav_regex(r"\invoice"), "invoice");
        assert_eq!(sanitize_clamav_regex(r"\pdf"), "pdf");
        assert_eq!(sanitize_clamav_regex(r"\.exe$"), r"\.exe$");
        // Literal '[' inside a class is escaped (nested-class avoidance).
        assert_eq!(sanitize_clamav_regex("[[Gg]"), r"[\[Gg]");
        // Non-quantifier braces become literal; real quantifiers are preserved.
        assert_eq!(sanitize_clamav_regex("po{x}"), r"po\{x\}");
        assert_eq!(sanitize_clamav_regex("a{2,4}"), "a{2,4}");

        // Real failing patterns from foxhole_*.cdb must now compile.
        assert_compiles(r"(?i)\.ord.\pdf\.exe$");
        assert_compiles(r"(?i)^po{.{0,30}}\.lnk$");
        assert_compiles("[. -_]([[Gg][Ii][Ff])(([. _,]){1,})([Ee][Xx][Ee])$");
        assert_compiles(r"[\* -_]([[Jj][Pp][Gg])(([\*]){1,})([Ss][Cc][Rr])$");
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::path::PathBuf;

    fn src() -> SourceLocation {
        SourceLocation {
            path: Arc::from(PathBuf::from("test.db").as_path()),
            line: 1,
        }
    }

    #[test]
    fn parses_old_db_name_equals_hex() {
        // `name=hexsig` → one generic (target None), offset-Any body signature.
        let mut arena = String::new();
        let sig = parse_db_signature("Worm.Test=414243", src(), &mut arena)
            .expect("ok")
            .expect("loaded");
        let s = sig.name.start as usize;
        assert_eq!(&arena[s..s + sig.name.len as usize], "Worm.Test");
        assert_eq!(sig.target, None);
        assert_eq!(sig.offset, OffsetSpec::any());
        assert!(!sig.patterns.is_empty());
    }

    #[test]
    fn skips_disabled_db_double_equals() {
        // `Name==…` is ClamAV's disabled marker: skipped, not an error.
        assert!(matches!(
            parse_db_signature("Foo.Bar==deadbeef", src(), &mut String::new()),
            Ok(None)
        ));
    }

    #[test]
    fn rejects_db_line_without_equals() {
        assert!(parse_db_signature("no-equals-here", src(), &mut String::new()).is_err());
    }

    #[test]
    fn sdb_parses_identically_to_ndb() {
        // `.sdb` routes through the ndb parser; same line → same result.
        let line = "Test.Sig:0:*:4142";
        let mut an = String::new();
        let mut as_ = String::new();
        let ndb = parse_extended_signature(line, src(), &mut an).unwrap().unwrap();
        let sdb = parse_extended_signature(line, src(), &mut as_).unwrap().unwrap();
        assert_eq!(&an[..], &as_[..]); // same interned name bytes
        assert_eq!(ndb.name, sdb.name); // identical span (both interned at offset 0)
        assert_eq!(ndb.target, sdb.target);
        assert_eq!(classify_extension("sdb"), ExtKind::BodyNdb);
    }

    #[test]
    fn classify_extension_covers_clamav_dispatch_table() {
        // Every extension in readdb.c's cli_load dispatch (lines ~4746-4852) must
        // resolve to a concrete ExtKind — guards against silent-drop regressions.
        // `.yar`/`.yara` are intentionally excluded: this crate delegates YARA to
        // the separate yara-x engine, so they are not handled here.
        let dispatched = [
            "db", "cvd", "cld", "cud", "crb", "hdb", "hsb", "hdu", "hsu", "fp", "sfp",
            "mdb", "msb", "imp", "mdu", "msu", "ndb", "ndu", "ldb", "ldu", "cbc", "sdb",
            "zmd", "rmd", "cfg", "info", "wdb", "pdb", "gdb", "ftm", "ign", "ign2", "idb",
            "cdb", "cat", "ioc", "pwdb",
        ];
        for ext in dispatched {
            assert_ne!(
                classify_extension(ext),
                ExtKind::Unknown,
                "extension '.{ext}' from the ClamAV dispatch table classified as Unknown"
            );
        }
        assert_eq!(classify_extension("totally-made-up"), ExtKind::Unknown);
    }
}

fn parse_encrypted(raw: &str) -> Result<Option<bool>, String> {
    match raw.trim() {
        "*" | "" => Ok(None),
        "0" => Ok(Some(false)),
        "1" => Ok(Some(true)),
        other => Err(format!("invalid IsEncrypted value '{other}'")),
    }
}

impl NumSpec {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() || raw == "*" {
            return Ok(NumSpec::Any);
        }
        if let Some(rest) = raw.strip_prefix('-') {
            return Ok(NumSpec::Range(None, Some(parse_u64(rest)?)));
        }
        if let Some(rest) = raw.strip_suffix('-') {
            return Ok(NumSpec::Range(Some(parse_u64(rest)?), None));
        }
        if let Some((lo, hi)) = raw.split_once('-') {
            let lo = parse_u64(lo)?;
            let hi = parse_u64(hi)?;
            if hi < lo {
                return Err(format!("invalid range '{raw}'"));
            }
            return Ok(NumSpec::Range(Some(lo), Some(hi)));
        }
        Ok(NumSpec::Exact(parse_u64(raw)?))
    }

    pub fn matches(&self, value: u64) -> bool {
        match self {
            NumSpec::Any => true,
            NumSpec::Exact(n) => value == *n,
            NumSpec::Range(lo, hi) => {
                lo.map_or(true, |l| value >= l) && hi.map_or(true, |h| value <= h)
            }
        }
    }

    pub fn is_constrained(&self) -> bool {
        !matches!(self, NumSpec::Any)
    }
}

fn parse_u64(raw: &str) -> Result<u64, String> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid number '{raw}'"))
}

fn parse_extended_signature(
    line: &str,
    source: SourceLocation,
    names: &mut String,
) -> Result<Option<ExtendedSignature>, String> {
    // name:target:offset:hex[:minFL[:maxFL]]
    let parts = line.splitn(6, ':').collect::<Vec<_>>();
    if parts.len() < 4 {
        return Err("extended signature needs name:target:offset:hex".to_string());
    }

    // Target: '*' → generic (None); a number must be in 0..CLI_MTARGETS, else the
    // signature is skipped (readdb.c cli_loadndb), as it can never select a root.
    const CLI_MTARGETS: u32 = 15;
    let target = match parts[1].trim() {
        "*" | "" => None,
        t => match t.parse::<u32>() {
            Ok(n) if n < CLI_MTARGETS => Some(n),
            Ok(_) => return Ok(None), // out-of-range target → skip
            Err(_) => return Err("invalid target field".to_string()),
        },
    };

    // Functionality-level gating: skip if minFL > engine or maxFL < engine.
    let flevel = crate::bytecode_vm::ENGINE_FLEVEL;
    if let Some(min_fl) = parts.get(4).and_then(|s| s.trim().parse::<u32>().ok()) {
        if min_fl > flevel {
            return Ok(None);
        }
    }
    if let Some(max_fl) = parts.get(5).and_then(|s| s.trim().parse::<u32>().ok()) {
        if max_fl < flevel {
            return Ok(None);
        }
    }

    let offset = OffsetSpec::parse(parts[2]);
    let patterns = compile_pattern_variants(parts[3], Modifiers::default())
        .map_err(|err| format!("invalid body pattern: {err}"))?;

    Ok(Some(ExtendedSignature {
        name: intern_name(names, parts[0]),
        target,
        offset,
        patterns: patterns.into_boxed_slice(),
        source,
    }))
}

/// Parse one old-format `.db` line: `MalwareName=HexSignature`.
///
/// Mirrors `cli_loaddb` (readdb.c): the signature is added to the generic root
/// (`root[0]`, i.e. target `None`) with offset `*` (anywhere). A line whose
/// pattern begins with `=` (i.e. `Name==…`) is skipped, exactly as ClamAV's
/// `if (*pt == '=') continue;`. The pattern is a standard hex body signature, so
/// it compiles through the same path as `.ndb`.
fn parse_db_signature(
    line: &str,
    source: SourceLocation,
    names: &mut String,
) -> Result<Option<ExtendedSignature>, String> {
    let (name, pattern) = line
        .split_once('=')
        .ok_or_else(|| "old-format .db signature needs name=hexsig".to_string())?;
    // `Name==…`: ClamAV skips these (the historical "disabled" marker).
    if pattern.starts_with('=') {
        return Ok(None);
    }
    let patterns = compile_pattern_variants(pattern, Modifiers::default())
        .map_err(|err| format!("invalid .db body pattern: {err}"))?;
    Ok(Some(ExtendedSignature {
        name: intern_name(names, name),
        target: None,
        offset: OffsetSpec::any(),
        patterns: patterns.into_boxed_slice(),
        source,
    }))
}

fn visit_database_dir(
    path: &Path,
    callback: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if path.is_file() {
        return callback(path);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            visit_database_dir(&path, callback)?;
        } else if path.is_file() {
            callback(&path)?;
        }
    }
    Ok(())
}

/// First pass over the database: build the set of signature names to ignore
/// from every `.ign`/`.ign2` file (ClamAV `cli_loadign` → `engine->ignored`).
fn collect_ignored(path: &Path, report: &mut LoadReport) -> io::Result<HashSet<Box<str>>> {
    let mut ignored = HashSet::new();
    visit_database_dir(path, &mut |file| {
        let ext = extension_key(file);
        if ext != "ign" && ext != "ign2" {
            return Ok(());
        }
        let f = File::open(file)?;
        let mut reader = BufReader::new(f);
        let mut raw: Vec<u8> = Vec::new();
        loop {
            raw.clear();
            if reader.read_until(b'\n', &mut raw)? == 0 {
                break;
            }
            let decoded = String::from_utf8_lossy(&raw);
            let line = decoded.trim_end_matches(['\r', '\n']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = ignored_signame(line) {
                ignored.insert(Box::from(name));
                report.ign_entries += 1;
            }
        }
        Ok(())
    })?;
    Ok(ignored)
}

/// Extract the signature name from one `.ign`/`.ign2` line, per `cli_loadign`:
/// 1 field → the whole line; 2 fields → field 0 (field 1 is an MD5 we don't
/// verify); 3+ fields (old format `db:line:name`) → field 2.
fn ignored_signame(line: &str) -> Option<&str> {
    let tokens: Vec<&str> = line.split(':').collect();
    let name = match tokens.len() {
        0 => return None,
        1 => line,
        2 => tokens[0],
        _ => tokens[2],
    };
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn push_error(report: &mut LoadReport, source: SourceLocation, message: String) {
    report.errors.push(LoadError { source, message });
}

fn push_unsupported(
    database: &mut Database,
    report: &mut LoadReport,
    source: SourceLocation,
    reason: String,
) {
    report.unsupported_records += 1;
    database.unsupported.push(UnsupportedRecord { source, reason });
}

fn extension_key(path: &Path) -> String {
    path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Classification of a ClamAV database file by extension, mirroring the dispatch
/// table in `clamav/libclamav/readdb.c` (`cli_load`, lines ~4746-4852). Every
/// extension ClamAV recognises maps to a non-`Unknown` variant so the loader can
/// account for 100% of the files it sees instead of silently dropping some.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtKind {
    /// `.ndb`/`.ndu`/`.sdb` — extended body signatures (parsed per line).
    BodyNdb,
    /// `.db` — old-format `name=hexsig` body signatures (parsed per line).
    BodyOldDb,
    /// `.ldb`/`.ldu` — logical signatures.
    Logical,
    /// `.cdb` — container metadata signatures.
    Container,
    /// `.ftm` — file-type magic.
    FileMagic,
    /// `.ign`/`.ign2` — ignore lists (consumed in the first pass).
    Ignore,
    /// Hash-based databases (whole-file, PE section, PE import, false-positive).
    Hash,
    /// `.pdb`/`.gdb`/`.wdb` — phishing URL/domain databases (Pass 2).
    Phishing,
    /// `.idb` — icon fuzzy-image signatures (Pass 3).
    Icon,
    /// `.crb` — Authenticode certificate trust/block rules (text, per-line).
    CertCrb,
    /// `.cat` — Authenticode catalog (binary PKCS#7); loader is a follow-up.
    CertCat,
    /// `.ioc` — OpenIOC XML indicator databases.
    Ioc,
    /// `.cfg` — dconf engine configuration (not detection).
    Config,
    /// `.info`/`.dat`/`.pwdb`/`.sign` — container metadata / archive passwords.
    Metadata,
    /// `.cvd`/`.cld`/`.cud`/`.cbc` — signed containers / bytecode, handled by the
    /// dedicated CVD/bytecode loader rather than the per-line database loader.
    ContainerDb,
    /// `.zmd`/`.rmd` — deprecated ClamAV metadata formats.
    Deprecated,
    /// Any extension not recognised by ClamAV's dispatch table.
    Unknown,
}

impl ExtKind {
    /// Human-readable disposition string recorded for a non-matched file, naming
    /// the exact reason and (where relevant) the follow-up pass that will add it.
    fn disposition(self, ext: &str) -> String {
        match self {
            ExtKind::Phishing => {
                format!("phishing URL/domain database '.{ext}' — not yet matched (Pass 2)")
            }
            ExtKind::Icon => {
                format!("icon fuzzy-image database '.{ext}' — not yet matched (Pass 3)")
            }
            ExtKind::CertCat => {
                format!("Authenticode catalog '.{ext}' (binary PKCS#7) — loader is a follow-up")
            }
            ExtKind::Ioc => format!("OpenIOC XML database '.{ext}' — not yet matched"),
            ExtKind::Config => format!("engine configuration '.{ext}' — not a detection database"),
            ExtKind::Metadata => {
                format!("container metadata / archive passwords '.{ext}' — not a detection database")
            }
            ExtKind::ContainerDb => {
                format!("signed container / bytecode '.{ext}' — loaded by the CVD/bytecode loader")
            }
            ExtKind::Deprecated => format!("deprecated ClamAV format '.{ext}'"),
            ExtKind::Unknown => format!("unknown ClamAV database extension '.{ext}'"),
            _ => format!("'.{ext}'"),
        }
    }
}

/// Map a lowercased extension (no leading dot) to its [`ExtKind`].
fn classify_extension(ext: &str) -> ExtKind {
    match ext {
        "ndb" | "ndu" | "sdb" => ExtKind::BodyNdb,
        "db" => ExtKind::BodyOldDb,
        "ldb" | "ldu" => ExtKind::Logical,
        "cdb" => ExtKind::Container,
        "ftm" => ExtKind::FileMagic,
        "ign" | "ign2" => ExtKind::Ignore,
        // Whole-file / PE-section / PE-import / false-positive hashes (cli_loadhash).
        "hdb" | "hdu" | "hsb" | "hsu" | "mdb" | "mdu" | "msb" | "msu" | "imp" | "fp"
        | "sfp" => ExtKind::Hash,
        "pdb" | "gdb" | "wdb" => ExtKind::Phishing,
        "idb" => ExtKind::Icon,
        "crb" => ExtKind::CertCrb,
        "cat" => ExtKind::CertCat,
        "ioc" => ExtKind::Ioc,
        "cfg" => ExtKind::Config,
        "info" | "dat" | "pwdb" | "sign" => ExtKind::Metadata,
        "cvd" | "cld" | "cud" | "cbc" => ExtKind::ContainerDb,
        "zmd" | "rmd" => ExtKind::Deprecated,
        _ => ExtKind::Unknown,
    }
}

fn parse_section_start(raw: &str) -> Option<OffsetAnchor> {
    let rest = raw.strip_prefix('S')?;
    let mut digits = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.peek() {
        if ch.is_ascii_digit() {
            digits.push(*ch);
            chars.next();
        } else {
            break;
        }
    }
    if digits.is_empty() {
        return None;
    }
    let index = digits.parse::<usize>().ok()?;
    let suffix: String = chars.collect();
    let delta = if suffix.is_empty() {
        0
    } else if let Some(rest) = suffix.strip_prefix('+') {
        parse_i64(rest)?
    } else if let Some(rest) = suffix.strip_prefix('-') {
        -parse_i64(rest)?
    } else {
        return None;
    };
    Some(OffsetAnchor::SectionStart { index, delta })
}

fn parse_i64(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok()
}

fn apply_delta(base: usize, delta: i64) -> Option<usize> {
    if delta >= 0 {
        base.checked_add(delta as usize)
    } else {
        base.checked_sub(delta.unsigned_abs() as usize)
    }
}

fn shifted_range(offset: usize, data_len: usize, max_shift: Option<usize>) -> Vec<(usize, usize)> {
    if offset > data_len {
        return Vec::new();
    }
    let end = offset.saturating_add(max_shift.unwrap_or(0)).min(data_len);
    vec![(offset, end)]
}
