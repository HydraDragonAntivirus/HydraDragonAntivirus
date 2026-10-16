use std::path::Path;
use hydradragonclamav::scanner::{Engine, ScanMatch, ScanOptions};

pub struct ClamScanner {
    engine: Option<Engine>,
}

impl ClamScanner {
    pub fn new(database_dir: &Path) -> Self {
        if !database_dir.exists() {
            return Self { engine: None };
        }

        match Engine::from_database_dir(database_dir) {
            Ok((engine, _report)) => Self { engine: Some(engine) },
            Err(_) => Self { engine: None },
        }
    }

    /// ClamAV file type (`CL_TYPE_*`) of `data`, by content (see
    /// `Engine::file_type_name`). None while the database is not loaded.
    pub fn file_type(&self, data: &[u8]) -> Option<String> {
        self.engine.as_ref()?.file_type_name(data)
    }

    pub fn is_loaded(&self) -> bool {
        self.engine.is_some()
    }

    pub fn scan_bytes(&self, data: &[u8], file_name: &str) -> Vec<ScanMatch> {
        let Some(ref engine) = self.engine else {
            return Vec::new();
        };

        let options = ScanOptions::default();
        if data.len() > options.max_child_size {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let direct = engine.scan_bytes_named(data, file_name, options, &[]);
        matches.extend(direct);

        // Recursive archive inspection via hydradragonextractor
        if options.scan_archives {
            if let Ok(entries) = hydradragonextractor::extract_archive_from_bytes(data, false) {
                for entry in entries {
                    let child_matches = engine.scan_bytes_named(&entry.data, &entry.name, options, &[]);
                    matches.extend(child_matches);
                }
            }
        }

        matches
    }

    /// Signature name and file byte range `[start, end)` of every byte-pattern match
    /// in `data` itself (archive members are not file offsets), at most `limit`.
    /// For in-place disinfection.
    pub fn match_ranges(&self, data: &[u8], file_name: &str, limit: usize) -> Vec<(String, usize, usize)> {
        let Some(ref engine) = self.engine else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for m in engine.scan_bytes_named(data, file_name, ScanOptions::default(), &[]) {
            if out.len() >= limit {
                break;
            }
            if m.object_path != file_name {
                continue; // an extracted member, its offsets are not file offsets
            }
            for (s, e) in engine.match_ranges(data, &m, limit - out.len()) {
                out.push((m.name.clone(), s, e));
            }
        }
        out
    }
}

/// One ClamAV match with where it came from, for the analyst "why" view.
#[derive(Debug, Clone)]
pub struct ClamExplain {
    pub name: String,
    /// `Extended` (.ndb), `Logical` (.ldb), `Container`, `Phishing`, `Yara`, `Heuristic`.
    pub kind: String,
    /// Database file and 1-based line of the signature (line 0: none).
    pub source: String,
    pub line: usize,
    /// The signature line itself from that database file (at most 4 KB).
    pub definition: Option<String>,
    /// Where it matched: the file itself, or an extracted member / PDF stream / data URI.
    pub object_path: String,
    /// `Raw`, or the ClamAV normalized view it matched in (`HtmlNormalized`, `JavaScript`, ...).
    pub view: String,
    /// File byte ranges `[start, end)` of the matched patterns (empty when the match is
    /// not a byte pattern of the file itself: normalized view, extracted member,
    /// PCRE / byte-compare / fuzzy subsignatures, heuristics).
    pub ranges: Vec<(usize, usize)>,
}

/// Line `line` (1-based) of `path`, trimmed, at most 4 KB.
pub fn database_line(path: &Path, line: usize) -> Option<String> {
    use std::io::BufRead;
    if line == 0 {
        return None;
    }
    let mut r = std::io::BufReader::new(std::fs::File::open(path).ok()?);
    let mut buf = Vec::new();
    for _ in 0..line {
        buf.clear();
        if r.read_until(b'\n', &mut buf).ok()? == 0 {
            return None;
        }
    }
    let mut text = String::from_utf8_lossy(&buf).trim().to_string();
    if text.len() > 4096 {
        let mut cut = 4096;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str(" …");
    }
    Some(text)
}

impl ClamScanner {
    /// Every ClamAV match of `data` (PUA included, extracted members and normalized
    /// views too) with its signature source, definition line and the file byte ranges
    /// it matched (at most `max_ranges` per match).
    pub fn explain(&self, data: &[u8], file_name: &str, max_ranges: usize) -> Vec<ClamExplain> {
        let Some(ref engine) = self.engine else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for m in engine.scan_bytes_named(data, file_name, ScanOptions::default(), &[]) {
            let raw = m.object_path == file_name && matches!(m.view, hydradragonclamav::ScanView::Raw);
            let ranges = if raw { engine.match_ranges(data, &m, max_ranges) } else { Vec::new() };
            out.push(ClamExplain {
                definition: database_line(&m.source.path, m.source.line),
                name: m.name,
                kind: format!("{:?}", m.kind),
                source: m.source.path.display().to_string(),
                line: m.source.line,
                object_path: m.object_path,
                view: format!("{:?}", m.view),
                ranges,
            });
        }
        out
    }
}
