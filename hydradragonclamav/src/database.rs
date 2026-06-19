use crate::logical::{parse_logical_signature, LogicalSignature};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use crate::pe::PeInfo;
use regex::Regex;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Database {
    pub extended: Vec<ExtendedSignature>,
    pub logical: Vec<LogicalSignature>,
    pub container: Vec<ContainerSignature>,
    pub file_type_magic: Vec<FileTypeMagic>,
    pub unsupported: Vec<UnsupportedRecord>,
}

#[derive(Clone, Debug)]
pub struct ExtendedSignature {
    pub name: String,
    pub target: Option<u32>,
    pub offset: OffsetSpec,
    pub patterns: Vec<Pattern>,
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
    pub name: String,
    pub container_type: ContainerType,
    pub container_size: NumSpec,
    pub filename: Option<Regex>,
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
    pub patterns: Vec<Pattern>,
    pub clamav_type: String,
    pub source: SourceLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    pub path: PathBuf,
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
    pub logical_loaded: usize,
    pub container_loaded: usize,
    pub ftm_loaded: usize,
    pub hash_files_skipped: usize,
    pub unsupported_files: usize,
    pub unsupported_records: usize,
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
        visit_database_dir(path.as_ref(), &mut |file| {
            load_file(file, &mut database, &mut report)
        })?;
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

fn load_file(path: &Path, database: &mut Database, report: &mut LoadReport) -> io::Result<()> {
    report.files_seen += 1;
    let ext = extension_key(path);
    *report.by_extension.entry(ext.clone()).or_insert(0) += 1;

    if is_hash_extension(&ext) {
        report.hash_files_skipped += 1;
        return Ok(());
    }

    if !matches!(
        ext.as_str(),
        "ndb" | "ndu" | "ldb" | "ldu" | "cdb" | "ftm"
    ) {
        if is_known_unsupported_extension(&ext) {
            report.unsupported_files += 1;
            push_unsupported(
                database,
                report,
                path,
                0,
                format!("unsupported non-body ClamAV database format '.{ext}'"),
            );
        }
        return Ok(());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        report.lines_seen += 1;
        let source = SourceLocation {
            path: path.to_path_buf(),
            line: line_number,
        };
        match ext.as_str() {
            "ndb" | "ndu" => match parse_extended_signature(line, source.clone()) {
                Ok(signature) => {
                    database.extended.push(signature);
                    report.extended_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            "ldb" | "ldu" => match parse_logical_signature(line, source.clone()) {
                Ok((signature, warnings)) => {
                    for warning in warnings {
                        push_unsupported(database, report, path, line_number, warning);
                    }
                    database.logical.push(signature);
                    report.logical_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            "cdb" => match parse_container_signature(line, source.clone()) {
                Ok(signature) => {
                    database.container.push(signature);
                    report.container_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            "ftm" => match parse_ftm(line, source.clone()) {
                Ok(signature) => {
                    database.file_type_magic.push(signature);
                    report.ftm_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            },
            _ => unreachable!(),
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
        name: parts[0].to_string(),
        container_type: cl_type_to_container(parts[1]),
        container_size: NumSpec::parse(parts[2])?,
        filename: parse_filename_regex(parts[3])?,
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
        // 0 = absolute byte comparison, 1 = body-pattern anywhere.
        "0" | "1" => OffsetSpec::parse(parts[1].trim()),
        other => return Err(format!("unsupported ftm magictype '{other}'")),
    };
    let patterns = compile_pattern_variants(parts[2].trim(), Modifiers::default())
        .map_err(|err| format!("invalid ftm magic bytes: {err}"))?;
    Ok(FileTypeMagic {
        offset,
        patterns,
        clamav_type: parts[5].trim().to_string(),
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

fn parse_filename_regex(raw: &str) -> Result<Option<Regex>, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" || raw == ".*" {
        return Ok(None);
    }
    Regex::new(raw)
        .map(Some)
        .map_err(|err| format!("invalid container filename regex: {err}"))
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
) -> Result<ExtendedSignature, String> {
    let parts = line.splitn(6, ':').collect::<Vec<_>>();
    if parts.len() < 4 {
        return Err("extended signature needs name:target:offset:hex".to_string());
    }

    let target = parts[1].parse::<u32>().ok();
    let offset = OffsetSpec::parse(parts[2]);
    let patterns = compile_pattern_variants(parts[3], Modifiers::default())
        .map_err(|err| format!("invalid body pattern: {err}"))?;

    Ok(ExtendedSignature {
        name: parts[0].to_string(),
        target,
        offset,
        patterns,
        source,
    })
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

fn push_error(report: &mut LoadReport, source: SourceLocation, message: String) {
    report.errors.push(LoadError { source, message });
}

fn push_unsupported(
    database: &mut Database,
    report: &mut LoadReport,
    path: &Path,
    line: usize,
    reason: String,
) {
    report.unsupported_records += 1;
    database.unsupported.push(UnsupportedRecord {
        source: SourceLocation {
            path: path.to_path_buf(),
            line,
        },
        reason,
    });
}

fn extension_key(path: &Path) -> String {
    path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_hash_extension(ext: &str) -> bool {
    matches!(
        ext,
        "hdb" | "hdu" | "hsb" | "hsu" | "mdb" | "mdu" | "msb" | "msu"
    )
}

fn is_known_unsupported_extension(ext: &str) -> bool {
    matches!(
        ext,
        "cbc"
            | "idb"
            | "pdb"
            | "gdb"
            | "wdb"
            | "fp"
            | "sfp"
            | "ign"
            | "ign2"
            | "cfg"
            | "cat"
            | "crb"
            | "info"
            | "pwdb"
            | "cvd"
            | "sign"
            | "dat"
    )
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
