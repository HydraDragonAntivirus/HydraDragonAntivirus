//! File type magic signature database (`--ftm`).
//!
//! Loads a text database of file type magic signatures in the classic FTM
//! layout and consults it during byte classification, so the resulting
//! [`crate::models::FileTypeInfo`] tags and flags match what the external
//! scanner/emulator components expect.
//!
//! Line format (1 entry per line, `#` comments, blank lines ignored):
//!
//! ```text
//! Name:Type:Offset:Magic[:MIN_FLC[:MAX_FLC[:ALIAS[:MAGIC_VERSION]]]]
//! ```
//!
//! * `Name` - display/type name; its normalized form becomes a file type tag
//!   and, when known, drives the dedicated flags (`is_zip`, `is_rar`, ...).
//! * `Type` - numeric type code, informational only (kept in the entry).
//! * `Offset` - 0-based byte offset of `Magic` in the file; a negative offset
//!   counts from EOF (`-7` = the magic must end 7 bytes before the end).
//! * `Magic` - comma-separated hex bytes; empty means "match any content at
//!   this offset" (useful with `MIN_FLC`).
//! * `MIN_FLC` / `MAX_FLC` - 0 = unbounded file length bounds.
//! * `ALIAS` - treats the entry as this type name instead of `Name`.
//!
//! The DB never ships in the crate: pass `--ftm FILE` (or
//! [`set_global_db`]) once; entries are matched with a fixed-offset compare,
//! so the cost per file is a handful of slice comparisons.
use crate::models::FileTypeInfo;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtmEntry {
    pub name: String,
    pub type_code: u16,
    /// Signed 0-based offset; negative counts from EOF.
    pub offset: i64,
    /// Empty means the offset match alone decides (see module docs).
    pub magic: Vec<u8>,
    pub min_file_len: u64,
    pub max_file_len: u64,
    pub alias: Option<String>,
    pub version: Option<String>,
}

/// Effective tag name of the entry (`ALIAS` wins over `Name`).
impl FtmEntry {
    pub fn type_name(&self) -> String {
        crate::scanner::filetype::normalize_file_type_alias(
            self.alias.as_deref().unwrap_or(&self.name),
        )
    }

    /// Every normalized name the entry answers to: `Name`, `ALIAS` and the
    /// effective [`Self::type_name`], without duplicates or empty names.
    pub fn type_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for name in [Some(self.type_name()), Some(crate::scanner::filetype::normalize_file_type_alias(&self.name)), self.alias.as_deref().map(crate::scanner::filetype::normalize_file_type_alias)].into_iter().flatten() {
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

static FTM_DB: Mutex<Option<Arc<Vec<FtmEntry>>>> = Mutex::new(None);

pub fn parse_magic(spec: &str) -> Result<Vec<u8>, String> {
    let value = spec.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let clean = token
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let byte = u8::from_str_radix(clean, 16).map_err(|_| {
            format!("invalid magic byte `{token}` (expected comma-separated hex like `4D,5A`)")
        })?;
        out.push(byte);
    }
    Ok(out)
}

pub fn parse_ftm_text(text: &str) -> Result<Vec<FtmEntry>, String> {
    let mut entries = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            return Err(format!(
                "line {} needs at least `Name:Type:Offset:Magic`: `{}`",
                line_no + 1,
                line
            ));
        }
        let type_code = fields[1]
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("line {}: invalid type code `{}`", line_no + 1, fields[1]))?;
        let offset_raw = fields[2].trim();
        let offset = offset_raw
            .parse::<i64>()
            .with_context(|| format!("line {}: invalid offset `{offset_raw}`", line_no + 1))
            .map_err(|e| format!("{e:#}"))?;
        let magic = parse_magic(fields[3]).map_err(|e| format!("line {}/1: {e}", line_no + 1))?;
        let min_file_len = fields
            .get(4)
            .map(|f| f.trim().parse::<u64>())
            .transpose()
            .map_err(|_| format!("line {}: invalid MIN_FLC `{}`", line_no + 1, fields[4]))?
            .unwrap_or(0);
        let max_file_len = fields
            .get(5)
            .map(|f| f.trim().parse::<u64>())
            .transpose()
            .map_err(|_| format!("line {}: invalid MAX_FLC `{}`", line_no + 1, fields[5]))?
            .unwrap_or(0);
        if min_file_len > 0 && max_file_len > 0 && min_file_len > max_file_len {
            return Err(format!(
                "line {}: MIN_FLC {} > MAX_FLC {}",
                line_no + 1,
                min_file_len,
                max_file_len
            ));
        }
        let alias = fields
            .get(6)
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty());
        let version = fields
            .get(7)
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty());
        let name = fields[0].trim().to_string();
        if name.is_empty() {
            return Err(format!("line {}: empty name", line_no + 1));
        }
        entries.push(FtmEntry {
            name,
            type_code,
            offset,
            magic,
            min_file_len,
            max_file_len,
            alias,
            version,
        });
    }
    Ok(entries)
}

/// Magic/offset/length decision. `magic` empty means "content at the offset
/// is irrelevant" and only the offset being inside the file decides.
pub fn matches_entry(entry: &FtmEntry, data: &[u8]) -> bool {
    if entry.min_file_len > 0 && (data.len() as u64) < entry.min_file_len {
        return false;
    }
    if entry.max_file_len > 0 && (data.len() as u64) > entry.max_file_len {
        return false;
    }
    let start = if entry.offset >= 0 {
        entry.offset as usize
    } else {
        let back = (-(entry.offset as i128)) as usize;
        if back == 0 || back > data.len() {
            return false;
        }
        data.len() - back
    };
    if entry.magic.is_empty() {
        return start < data.len();
    }
    let end = match start.checked_add(entry.magic.len()) {
        Some(end) if end <= data.len() => end,
        _ => return false,
    };
    &data[start..end] == entry.magic.as_slice()
}

/// Loads an FTM text file (see [`parse_ftm_text`]).
pub fn load_ftm_file(path: &Path) -> Result<Vec<FtmEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read ftm {}", path.display()))?;
    parse_ftm_text(&text).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Installs a loaded FTM as the classification DB. Returns the entry count.
pub fn install(entries: Vec<FtmEntry>) -> usize {
    let len = entries.len();
    *FTM_DB.lock().unwrap() = Some(Arc::new(entries));
    len
}

pub fn set_global_db(path: &Path) -> Result<usize> {
    let entries = load_ftm_file(path)?;
    let count = entries.len();
    install(entries);
    eprintln!(
        "[HydraDragonSig] file type magic DB: {} entries from {}",
        count,
        path.display()
    );
    Ok(count)
}

/// Entries of the globally installed DB, if any.
pub fn global_entries() -> Option<Arc<Vec<FtmEntry>>> {
    FTM_DB.lock().unwrap().clone()
}

/// True when `normalized` (see `normalize_file_type_alias`) is the `Name`,
/// `ALIAS` or type name of an entry of the installed DB.
pub fn is_known_type_name(normalized: &str) -> bool {
    global_entries().is_some_and(|entries| entries.iter().any(|e| e.type_names().iter().any(|n| n == normalized)))
}

/// Flag key of a normalized tag: a namespaced `<prefix>_type_<name>` tag maps
/// like its bare `<name>` (`x_type_zip` raises the same flags as `zip`).
fn flag_key(tag: &str) -> &str {
    match tag.find("_type_") {
        Some(pos) if pos > 0 && pos + 6 < tag.len() => &tag[pos + 6..],
        _ => tag,
    }
}

/// Applies the magic DB to a freshly classified [`FileTypeInfo`]:
/// matched entries contribute their (lowercase-normalized) type tag, known
/// names raise the dedicated flags, and an unresolved `primary` adopts the
/// first matched type name. No-op when no DB is installed.
pub fn apply_to_info(info: &mut FileTypeInfo, data: &[u8]) {
    let Some(entries) = global_entries() else { return };
    for entry in entries.iter() {
        if !matches_entry(entry, data) {
            continue;
        }
        let tag = entry.type_name();
        if tag.is_empty() || info.tags.iter().any(|t| t == &tag) {
            continue;
        }
        // `Name` and `ALIAS` both become tags, so `file_type` conditions and the
        // type filters match the entry under either name as written in the DB.
        let names = entry.type_names();
        for name in &names {
            if !info.tags.iter().any(|t| t == name) {
                info.tags.push(name.clone());
            }
        }
        for name in &names {
            match flag_key(name) {
                "msexe" | "msexecab" | "exe" | "dll" | "sys" | "pe" => {
                    info.is_pe = true;
                    info.is_binary = true;
                }
                "elf" => info.is_elf = true,
                "mach_o" | "macho" => info.is_macho = true,
                "zip" => {
                    info.is_zip = true;
                    info.is_archive = true;
                }
                "rar" | "rar5" => {
                    info.is_rar = true;
                    info.is_archive = true;
                }
                "mscab" | "archive" => info.is_archive = true,
                "gzip" | "gz" => {
                    info.is_gzip = true;
                    info.is_archive = true;
                }
                "tar" => {
                    info.is_tar = true;
                    info.is_archive = true;
                }
                "7z" => {
                    info.is_7z = true;
                    info.is_archive = true;
                }
                "jar" => {
                    info.is_jar = true;
                    info.is_archive = true;
                }
                "pdf" => {
                    info.is_pdf = true;
                    info.is_binary = true;
                }
                "msole2" | "ole2" | "compound" => {
                    info.is_office = true;
                    info.is_microsoft_compound = true;
                }
                "dex" => info.is_dex = true,
                "java_class" | "class" => info.is_java_class = true,
                "mime" | "mail" | "html" => {
                    info.is_plain_text = true;
                    info.is_binary = false;
                }
                "script" | "perl" | "php" | "python" | "bash" | "shell" | "vbs" => {
                    info.is_plain_text = true;
                    info.is_script = true;
                    info.is_binary = false;
                }
                _ => {}
            }
        }
        if info.primary == "unknown" || info.primary.is_empty() {
            info.primary = tag.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ftm_lines() {
        let db = parse_ftm_text(
            "# comment\nMYTYPE:9:2:48,59:4:0:alias_t\nZIP:3:0:50,4B,05,06\nTRAIL:5:-4:1D,9D\n",
        )
        .unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db[0].name, "MYTYPE");
        assert_eq!(db[0].magic, vec![0x48, 0x59]);
        assert_eq!(db[0].min_file_len, 4);
        assert_eq!(db[0].alias.as_deref(), Some("alias_t"));
        assert_eq!(db[1].type_name(), "zip");
        // Negative offset counts from EOF: the magic must occupy [len-4, len-2).
        assert!(matches_entry(&db[2], &[0xAB, 0x1D, 0x9D, 0xAB, 0xCD]));
        assert!(matches_entry(&db[0], &[0xBB, 0x00, 0x48, 0x59])); // MIN_FLC=4 met
        assert!(!matches_entry(&db[0], &[0x48, 0x59])); // too short (MIN_FLC=4)
        assert!(matches_entry(&db[1], &[0x50, 0x4B, 0x05, 0x06, 0xFF, 0x06]));
    }

    #[test]
    fn invalid_lines_bail() {
        assert!(parse_ftm_text("short:1:2\n").is_err());
        assert!(parse_ftm_text("bad:99:0:ZZ\n").is_err());
    }
}
