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
}
