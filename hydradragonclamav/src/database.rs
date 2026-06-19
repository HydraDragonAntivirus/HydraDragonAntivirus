use crate::logical::{parse_logical_signature, LogicalSignature};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use crate::pe::PeInfo;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Database {
    pub extended: Vec<ExtendedSignature>,
    pub logical: Vec<LogicalSignature>,
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

    if !matches!(ext.as_str(), "ndb" | "ndu" | "ldb" | "ldu") {
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
        if matches!(ext.as_str(), "ndb" | "ndu") {
            match parse_extended_signature(line, source.clone()) {
                Ok(signature) => {
                    database.extended.push(signature);
                    report.extended_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            }
        } else {
            match parse_logical_signature(line, source.clone()) {
                Ok((signature, warnings)) => {
                    for warning in warnings {
                        push_unsupported(database, report, path, line_number, warning);
                    }
                    database.logical.push(signature);
                    report.logical_loaded += 1;
                }
                Err(message) => push_error(report, source, message),
            }
        }
    }
    Ok(())
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
        "cdb"
            | "cbc"
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
            | "ftm"
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
