//! False-positive signature lists (dashboard): turning off a signature that flags
//! clean files, with the reason kept next to it.
//!
//! * ClamAV: `<rules>/database/<file>.ign2` — ClamAV's own ignore list, read by
//!   hydradragonclamav when the engine (re)loads.
//! * HydraDragonSig: `<hydradragonsig_rules>/<file>.ign2` — same format, the
//!   engine drops the listed rule ids when it (re)loads.
//! * YARA: `<yara_rules>/<file>.ign2` — the engine drops matches of the listed
//!   rules when it (re)loads; `remove_excluded_rules.py -x <file>.ign2` removes them
//!   from the sources for good before the next `.yrc` build.
//!
//! Every entry is written as a `#` comment block (date, analyst, sample, reason)
//! followed by the signature name.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    ClamAv,
    HydraSig,
    Yara,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "clamav" => Some(Kind::ClamAv),
            "hydrasig" => Some(Kind::HydraSig),
            "yara" => Some(Kind::Yara),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Kind::ClamAv => "clamav",
            Kind::HydraSig => "hydrasig",
            Kind::Yara => "yara",
        }
    }

    pub fn ext(self) -> &'static str {
        "ign2"
    }

    pub fn default_file(self) -> &'static str {
        "multron_fp.ign2"
    }

    pub const ALL: [Kind; 3] = [Kind::ClamAv, Kind::HydraSig, Kind::Yara];

    /// Folder of the list files for this engine.
    pub fn dir(self, rules: &Path) -> PathBuf {
        match self {
            Kind::ClamAv => rules.join("database"),
            Kind::HydraSig => [
                rules.join("hydradragonsig_rules"),
                rules.join("rules").join("hydradragonsig"),
                rules.join("yara_rules").join("hydradragonsig_rules"),
            ]
            .into_iter()
            .find(|d| d.is_dir())
            .unwrap_or_else(|| rules.join("hydradragonsig_rules")),
            // Same folder the engine loads the YARA rules (.yrc / .yar) from.
            Kind::Yara => {
                if rules.join("yara_rules").is_dir() {
                    rules.join("yara_rules")
                } else {
                    rules.join("rules")
                }
            }
        }
    }

    /// The engine applies the list when it reloads (YARA: only after the rule is
    /// removed from the sources and the `.yrc` recompiled).
    pub fn note(self) -> &'static str {
        match self {
            Kind::ClamAv | Kind::HydraSig => "Active after the next engine reload.",
            Kind::Yara => "Active after the next engine reload. To remove the rule from the sources for good: remove_excluded_rules.py -x <this file>, then rebuild the .yrc.",
        }
    }
}

/// One detection named in a scan result.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    /// Engine layer as reported (e.g. `ClamAV`, `Unpacked_YARA`, `HydraSig`, `PE_ML`).
    pub layer: String,
    /// `clamav`, `yara`, `hydrasig`, `analyst` or `other` (not by name: ML, signer...).
    pub kind: &'static str,
    /// Signature name with the origin prefixes (`Unpacked:`, `Archive:x:` ...) removed.
    pub name: String,
    /// Name as reported.
    pub raw: String,
}

fn strip_origin(mut name: &str) -> &str {
    loop {
        let before = name;
        for p in ["Memory:", "Unpacked:", "Stripped:", "Overlay:"] {
            if let Some(rest) = name.strip_prefix(p) {
                name = rest;
            }
        }
        if let Some(rest) = name.strip_prefix("Archive:") {
            // `Archive:<entry>:<name>`: the entry name may itself contain ':'.
            name = rest.rsplit_once(':').map(|(_, n)| n).unwrap_or(rest);
        }
        if name == before {
            return name.trim();
        }
    }
}

fn kind_of_layer(layer: &str) -> &'static str {
    if layer.ends_with("ClamAV") {
        "clamav"
    } else if layer.ends_with("YARA") {
        "yara"
    } else if layer.ends_with("HydraSig") {
        "hydrasig"
    } else {
        "other"
    }
}

/// Detections in a result `detail` string (`Name (Layer), Name (Layer) — ...` and
/// `Analyst signature (engine): Name`).
pub fn parse_detail(detail: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    for seg in detail.split(" — ") {
        let seg = seg.trim();
        if seg.starts_with('[') {
            continue;
        }
        if let Some(rest) = seg.strip_prefix("Analyst signature (") {
            if let Some((engine, name)) = rest.split_once("): ") {
                out.push(Detection { layer: format!("analyst/{engine}"), kind: "analyst", name: name.trim().to_string(), raw: name.trim().to_string() });
            }
            continue;
        }
        for part in seg.split(", ") {
            let part = part.trim();
            let Some(open) = part.rfind(" (") else { continue };
            if !part.ends_with(')') {
                continue;
            }
            let layer = &part[open + 2..part.len() - 1];
            if layer.is_empty() || !layer.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let raw = &part[..open];
            let det = Detection { layer: layer.to_string(), kind: kind_of_layer(layer), name: strip_origin(raw).to_string(), raw: raw.to_string() };
            if !out.iter().any(|d| d.kind == det.kind && d.name == det.name) {
                out.push(det);
            }
        }
    }
    out
}

/// A list file name chosen by the analyst: letters, digits, `_ - .`, with the
/// engine's extension added when missing.
pub fn clean_file_name(kind: Kind, file: &str) -> Result<String, String> {
    let file = file.trim();
    let file = if file.is_empty() { kind.default_file() } else { file };
    let stem = file.strip_suffix(&format!(".{}", kind.ext())).unwrap_or(file);
    if stem.is_empty() || stem.len() > 64 || !stem.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) || stem.starts_with('.') {
        return Err("file name: use letters, digits, '_', '-' and '.' (at most 64)".into());
    }
    Ok(format!("{stem}.{}", kind.ext()))
}

fn check_name(kind: Kind, name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 256 || name.chars().any(|c| c.is_control()) {
        return Err("invalid signature name".into());
    }
    match kind {
        Kind::ClamAv if name.contains(':') => Err("a ClamAV signature name cannot contain ':'".into()),
        Kind::Yara if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
            Err("a YARA rule name has only letters, digits and '_'".into())
        }
        _ => Ok(()),
    }
}

fn one_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().chars().take(500).collect()
}

/// Names listed in a file (non-comment, non-empty lines; `Name:md5` -> `Name`).
fn listed_names(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|l| l.split(':').next().unwrap_or("").trim().to_string())
        .collect()
}

pub struct AddRequest<'a> {
    pub kind: Kind,
    pub name: &'a str,
    pub file: &'a str,
    pub reason: &'a str,
    pub analyst: &'a str,
    pub sha256: &'a str,
    pub file_name: &'a str,
}

/// Appends an entry. Returns the list path, or an error (also when the name is
/// already listed in any list of that engine).
pub fn add(rules: &Path, r: &AddRequest) -> Result<PathBuf, String> {
    check_name(r.kind, r.name)?;
    let reason = one_line(r.reason);
    if reason.len() < 3 {
        return Err("write the reason (why it is a false positive)".into());
    }
    let file = clean_file_name(r.kind, r.file)?;
    let dir = r.kind.dir(rules);
    for l in list(rules, r.kind).files {
        if l.entries.iter().any(|e| e.name == r.name) {
            return Err(format!("{} is already listed in {}", r.name, l.file));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&file);
    let mut block = String::new();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with('\n') {
        block.push('\n');
    }
    if !existing.is_empty() {
        block.push('\n');
    }
    block.push_str(&format!(
        "# {} | analyst: {} | sample: {} {}\n# reason: {}\n{}\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        one_line(if r.analyst.trim().is_empty() { "analyst" } else { r.analyst }),
        one_line(r.sha256),
        one_line(r.file_name),
        reason,
        r.name
    ));
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(block.as_bytes()))
        .map_err(|e| e.to_string())?;
    Ok(path)
}

/// Removes an entry and the comment block written above it.
pub fn remove(rules: &Path, kind: Kind, file: &str, name: &str) -> Result<(), String> {
    let file = clean_file_name(kind, file)?;
    let path = kind.dir(rules).join(&file);
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let crlf = text.contains("\r\n");
    let mut lines: Vec<&str> = text.lines().collect();
    let Some(pos) = lines.iter().position(|l| {
        let t = l.trim();
        !t.starts_with('#') && t.split(':').next().unwrap_or("").trim() == name
    }) else {
        return Err(format!("{name} is not in {file}"));
    };
    let mut start = pos;
    while start > 0 && lines[start - 1].trim_start().starts_with('#') {
        start -= 1;
    }
    // The blank line that separated this block from the previous one.
    if start > 0 && lines[start - 1].trim().is_empty() {
        start -= 1;
    }
    lines.drain(start..=pos);
    while lines.first().is_some_and(|l| l.trim().is_empty()) {
        lines.remove(0);
    }
    let nl = if crlf { "\r\n" } else { "\n" };
    let mut out = lines.join(nl);
    if !out.is_empty() {
        out.push_str(nl);
    }
    std::fs::write(&path, out).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub name: String,
    /// Comment lines directly above the name, without `# `.
    pub comment: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListFile {
    pub file: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KindLists {
    pub kind: &'static str,
    pub dir: String,
    pub default_file: &'static str,
    pub note: &'static str,
    pub files: Vec<ListFile>,
}

/// Every list file of an engine with its entries (ClamAV: `.ign2` and `.ign`).
pub fn list(rules: &Path, kind: Kind) -> KindLists {
    let dir = kind.dir(rules);
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
                p.is_file() && (ext == "ign2" || ext == "ign")
            })
            .collect();
        paths.sort();
        for p in paths {
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let mut entries = Vec::new();
            let mut comment: Vec<String> = Vec::new();
            for l in text.lines() {
                let t = l.trim();
                if t.is_empty() {
                    comment.clear();
                } else if let Some(c) = t.strip_prefix('#').or_else(|| t.strip_prefix("//")) {
                    comment.push(c.trim().to_string());
                } else {
                    entries.push(Entry { name: t.split(':').next().unwrap_or("").trim().to_string(), comment: std::mem::take(&mut comment) });
                }
            }
            files.push(ListFile { file: p.file_name().unwrap_or_default().to_string_lossy().into_owned(), entries });
        }
    }
    let _ = listed_names;
    KindLists { kind: kind.id(), dir: dir.display().to_string(), default_file: kind.default_file(), note: kind.note(), files }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_detail() {
        let d = parse_detail("Analyst signature (clamav): Trojan.Win32.X.A — Win.Trojan.Agent-1 (ClamAV), Unpacked:Generic_Rule (Unicorn_Unpacker_YARA), Archive:a:b.exe:HDS_1 (Archive_HydraSig), MalwareNet.PE.HighConfidence (PE_ML) — [Unicorn Unpacked: 1 PE (3 KB)]");
        let v: Vec<(&str, &str)> = d.iter().map(|x| (x.kind, x.name.as_str())).collect();
        assert_eq!(v, vec![("analyst", "Trojan.Win32.X.A"), ("clamav", "Win.Trojan.Agent-1"), ("yara", "Generic_Rule"), ("hydrasig", "HDS_1"), ("other", "MalwareNet.PE.HighConfidence")]);
    }

    #[test]
    fn add_list_remove() {
        let dir = std::env::temp_dir().join(format!("fpig{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("database")).unwrap();
        let req = |name: &'static str| AddRequest { kind: Kind::ClamAv, name, file: "my", reason: "clean installer", analyst: "E", sha256: "ab", file_name: "x.exe" };
        let p = add(&dir, &req("Win.A-1")).unwrap();
        add(&dir, &req("Win.B-2")).unwrap();
        assert!(add(&dir, &req("Win.A-1")).is_err());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("# reason: clean installer\nWin.A-1\n"));
        let l = list(&dir, Kind::ClamAv);
        assert_eq!(l.files[0].file, "my.ign2");
        assert_eq!(l.files[0].entries.len(), 2);
        assert_eq!(l.files[0].entries[1].comment[1], "reason: clean installer");
        remove(&dir, Kind::ClamAv, "my.ign2", "Win.A-1").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("Win.A-1") && text.contains("Win.B-2") && !text.starts_with('\n'));
        assert!(clean_file_name(Kind::Yara, "../x").is_err());
        assert_eq!(clean_file_name(Kind::Yara, "").unwrap(), "multron_fp.ign2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
