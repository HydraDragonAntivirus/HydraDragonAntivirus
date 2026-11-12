#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use hydradragonclamav::{Engine, ScanOptions, ScanView};

use crate::types::{self, Error, ScanResult};

/// Scan options tuned for a malware verdict: stop at the first signature match.
/// A file is malicious as soon as one signature fires, so there's no reason to
/// keep scanning for more — this is the per-file "stop on first match".
fn first_match_options() -> ScanOptions {
    ScanOptions {
        max_matches: 1,
        ..ScanOptions::default()
    }
}

/// Classify the database a matched signature came from. ClamAV's official
/// databases are `main`, `daily`, and `bytecode` (any extracted/versioned form);
/// every other database file (Sanesecurity, SecuriteInfo, MiscreantPunch, …) is
/// an unofficial third-party source, which the UI tags so users can weigh it.
fn is_unofficial_db(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    !(stem.starts_with("main") || stem.starts_with("daily") || stem.starts_with("bytecode"))
}

/// Pure-Rust ClamAV-compatible engine. Signatures are loaded directly from the
/// ClamAV database directory (.ndb/.ndu/.ldb/.ldu) and matched in-process, so
/// no native ClamAV runtime is required.
pub struct Scanner {
    // RwLock (not Mutex): scans take a shared read lock so many files can be
    // scanned concurrently; only reload_database takes the write lock.
    engine: RwLock<Engine>,
    dbpath: PathBuf,
    /// Total ClamAV detection signatures loaded (extended + logical).
    signatures_loaded: usize,
}

impl Scanner {
    /// Number of ClamAV signatures loaded into this engine.
    pub fn signature_count(&self) -> usize {
        self.signatures_loaded
    }
}

impl Scanner {
    /// Load the engine from a ClamAV database directory.
    pub fn new<P: AsRef<Path>>(dbpath: P) -> Result<Self, Error> {
        let dbpath = dbpath.as_ref().to_path_buf();
        if !dbpath.exists() {
            return Err(Error::DatabasePath(dbpath.to_string_lossy().into_owned()));
        }
        if !dbpath.is_dir() {
            return Err(Error::DatabasePath(format!(
                "Not a directory: {}",
                dbpath.to_string_lossy()
            )));
        }

        let (engine, report) =
            Engine::from_database_dir(&dbpath).map_err(|e| Error::DatabaseLoad(e.to_string()))?;

        // Count only actual detection signatures. Container (.cdb) and file-type
        // magic (.ftm) records are scan-support metadata, not signatures, so
        // including them made the displayed count larger than the real number.
        let signatures_loaded = report.extended_loaded + report.logical_loaded;
        eprintln!(
            "[ClamAV] hydradragonclamav engine ready. Signatures loaded: {} (extended {}, logical {}; +container {}, ftm {} support records)",
            signatures_loaded,
            report.extended_loaded,
            report.logical_loaded,
            report.container_loaded,
            report.ftm_loaded,
        );

        Ok(Self {
            engine: RwLock::new(engine),
            dbpath,
            signatures_loaded,
        })
    }

    /// Scan a single file. `_heuristics` is accepted for call-site compatibility;
    /// hydradragonclamav has no separate heuristic mode, so it has no effect.
    pub fn scan_file<P: AsRef<Path>>(
        &self,
        path: P,
        _heuristics: bool,
    ) -> Result<ScanResult, Error> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::FileNotFound(path.to_string_lossy().into_owned()));
        }
        if !path.is_file() {
            return Err(Error::NotRegularFile(path.to_string_lossy().into_owned()));
        }

        let bytes_scanned = path.metadata().map(|m| m.len()).unwrap_or(0);

        let matches = {
            let engine = self.engine.read().unwrap();
            engine
                .scan_path(path, first_match_options())
                .map_err(Error::Io)?
        };

        // Arenas are only file-mappable for raw matches on the top-level object
        // (an object_path with no `#archive[...]` segment).
        let arenas: Vec<(usize, usize)> = matches
            .iter()
            .filter(|m| m.view == ScanView::Raw && !m.object_path.contains('#'))
            .flat_map(|m| m.arenas.iter().copied())
            .collect();

        let result = match matches.first() {
            Some(first) => ScanResult {
                result_code: types::CL_VIRUS,
                virus_name: first.name.clone(),
                bytes_scanned,
                arenas,
                unofficial: is_unofficial_db(&first.source.path),
            },
            None => ScanResult {
                result_code: types::CL_CLEAN,
                virus_name: String::new(),
                bytes_scanned,
                arenas: Vec::new(),
                unofficial: false,
            },
        };

        Ok(result)
    }

    /// Scan an already-read byte buffer (same engine as [`scan_file`], which is
    /// itself just `fs::read` + a bytes scan — so this lets the caller read the
    /// file only once). `hydradragonclamav` does no path-specific unpacking.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult, Error> {
        self.scan_bytes_with(data, first_match_options())
    }

    /// Scan collecting **all** matches (not just the first), so the returned
    /// `arenas` cover every malicious byte range. Used by the disinfector to
    /// neutralize all infected regions — the fast verdict path (`scan_bytes`)
    /// stops at the first match, which is not enough for disinfection.
    pub fn scan_bytes_all(&self, data: &[u8]) -> Result<ScanResult, Error> {
        self.scan_bytes_with(data, ScanOptions::default())
    }

    fn scan_bytes_with(&self, data: &[u8], options: ScanOptions) -> Result<ScanResult, Error> {
        let bytes_scanned = data.len() as u64;
        let matches = {
            let engine = self.engine.read().unwrap();
            engine.scan_bytes(data, options)
        };
        let arenas: Vec<(usize, usize)> = matches
            .iter()
            .filter(|m| m.view == ScanView::Raw && !m.object_path.contains('#'))
            .flat_map(|m| m.arenas.iter().copied())
            .collect();
        let result = match matches.first() {
            Some(first) => ScanResult {
                result_code: types::CL_VIRUS,
                virus_name: first.name.clone(),
                bytes_scanned,
                arenas,
                unofficial: is_unofficial_db(&first.source.path),
            },
            None => ScanResult {
                result_code: types::CL_CLEAN,
                virus_name: String::new(),
                bytes_scanned,
                arenas: Vec::new(),
                unofficial: false,
            },
        };
        Ok(result)
    }

    /// Reload signatures from the database directory. Returns the number of
    /// signatures loaded.
    pub fn reload_database(&self) -> Result<u32, Error> {
        let (engine, report) = Engine::from_database_dir(&self.dbpath)
            .map_err(|e| Error::DatabaseLoad(e.to_string()))?;
        let signatures_loaded = (report.extended_loaded + report.logical_loaded) as u32;
        *self.engine.write().unwrap() = engine;
        Ok(signatures_loaded)
    }

    /// Engine version string.
    pub fn version(&self) -> Option<String> {
        Some(format!("hydradragonclamav {}", env!("CARGO_PKG_VERSION")))
    }
}
