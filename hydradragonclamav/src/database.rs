use crate::logical::{parse_logical_signature, LogicalSignature};
use crate::pattern::{compile_pattern_variants, Modifiers, Pattern};
use crate::pe::PeInfo;
use regex::Regex;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Database {
    pub extended: Vec<ExtendedSignature>,
    pub logical: Vec<LogicalSignature>,
    pub container: Vec<ContainerSignature>,
    pub file_type_magic: Vec<FileTypeMagic>,
    pub unsupported: Vec<UnsupportedRecord>,
    /// Decoded + interpreter-prepared ClamBC programs. A logical signature whose
    /// `bytecode` field is `Some(i)` is a bytecode trigger that runs `[i]`.
    pub bytecode_programs: Vec<crate::bytecode_vm::Bc>,
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
    pub logical_loaded: usize,
    pub container_loaded: usize,
    pub ftm_loaded: usize,
    pub hash_files_skipped: usize,
    pub unsupported_files: usize,
    pub unsupported_records: usize,
    pub bytecodes_loaded: usize,
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
    let mut reader = BufReader::new(file);
    // One shared path allocation for every signature from this file.
    let src_path: Arc<Path> = Arc::from(path);
    // ClamAV signature databases are NOT guaranteed to be valid UTF-8 — malware
    // names and some fields can carry stray bytes. Read raw bytes per line and
    // decode lossily so a single bad byte never aborts the entire database load
    // (which previously disabled the whole ClamAV engine).
    let mut raw: Vec<u8> = Vec::new();
    let mut index = 0usize;
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        let line_number = index + 1;
        index += 1;
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
    let sanitized = sanitize_clamav_regex(raw);
    Regex::new(&sanitized)
        .map(Some)
        .map_err(|err| format!("invalid container filename regex: {err}"))
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
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(n + 8);
    let mut i = 0;
    let mut in_class = false;
    let mut class_pos = 0usize; // position within the current [...] class

    while i < n {
        let c = chars[i];

        // Escapes: keep recognized ones, drop the backslash only from unknown
        // *letter* escapes (e.g. `\i`, `\p`) so they become literals. Keep it for
        // digits (so backreferences like `\1` stay unsupported, not silently
        // turned into a literal digit), punctuation, and recognized escapes.
        if c == '\\' {
            if i + 1 < n {
                let next = chars[i + 1];
                let drop = next.is_ascii_alphabetic() && !ESCAPE_LETTERS.contains(next);
                if !drop {
                    out.push('\\');
                }
                out.push(next);
                i += 2;
                if in_class {
                    class_pos += 1;
                }
            } else {
                out.push('\\'); // trailing backslash — Regex::new will report it
                i += 1;
            }
            continue;
        }

        if in_class {
            match c {
                // A literal ']' at the very start of a class (POSIX) needs escaping.
                ']' if class_pos == 0 => out.push_str("\\]"),
                ']' => {
                    in_class = false;
                    out.push(']');
                }
                // Literal '[' inside a class (but not a POSIX `[:name:]`) — escape
                // so Rust doesn't parse it as a nested class.
                '[' if !(i + 1 < n && chars[i + 1] == ':') => out.push_str("\\["),
                _ => out.push(c),
            }
            if !(c == ']' && !in_class) {
                class_pos += 1;
            }
            i += 1;
            continue;
        }

        match c {
            '[' => {
                in_class = true;
                class_pos = 0;
                out.push('[');
                i += 1;
                if i < n && chars[i] == '^' {
                    out.push('^');
                    i += 1;
                }
            }
            '{' => {
                if let Some(len) = quantifier_len(&chars, i) {
                    for ch in &chars[i..i + len] {
                        out.push(*ch);
                    }
                    i += len;
                } else {
                    out.push_str("\\{"); // not a quantifier — literal brace
                    i += 1;
                }
            }
            '}' => {
                out.push_str("\\}"); // stray closing brace — literal
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// If `chars[start]` begins a valid `{n}` / `{n,}` / `{n,m}` quantifier, return
/// its length (including the braces); otherwise `None` (so it's a literal `{`).
fn quantifier_len(chars: &[char], start: usize) -> Option<usize> {
    let n = chars.len();
    let mut j = start + 1;
    let digits_start = j;
    while j < n && chars[j].is_ascii_digit() {
        j += 1;
    }
    if j == digits_start {
        return None; // need at least one digit
    }
    if j < n && chars[j] == ',' {
        j += 1;
        while j < n && chars[j].is_ascii_digit() {
            j += 1;
        }
    }
    if j < n && chars[j] == '}' {
        Some(j - start + 1)
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
            path: Arc::from(path),
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
