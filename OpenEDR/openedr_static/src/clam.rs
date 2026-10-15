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
