#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hydradragonclamav::{Engine, ScanOptions, ScanView};

use crate::types::{self, Error, ScanResult};

/// Pure-Rust ClamAV-compatible engine. Signatures are loaded directly from the
/// ClamAV database directory (.ndb/.ndu/.ldb/.ldu) and matched in-process, so
/// no native ClamAV runtime is required.
pub struct Scanner {
    engine: Mutex<Engine>,
    dbpath: PathBuf,
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

        let signatures_loaded = report.extended_loaded + report.logical_loaded;
        eprintln!(
            "[ClamAV] hydradragonclamav engine ready. Signatures loaded: {} (extended {}, logical {})",
            signatures_loaded, report.extended_loaded, report.logical_loaded
        );

        Ok(Self {
            engine: Mutex::new(engine),
            dbpath,
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
            let engine = self.engine.lock().unwrap();
            engine
                .scan_path(path, ScanOptions::default())
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
            },
            None => ScanResult {
                result_code: types::CL_CLEAN,
                virus_name: String::new(),
                bytes_scanned,
                arenas: Vec::new(),
            },
        };

        Ok(result)
    }

    /// Scan an already-read byte buffer (same engine as [`scan_file`], which is
    /// itself just `fs::read` + a bytes scan — so this lets the caller read the
    /// file only once). `hydradragonclamav` does no path-specific unpacking.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult, Error> {
        let bytes_scanned = data.len() as u64;
        let matches = {
            let engine = self.engine.lock().unwrap();
            engine.scan_bytes(data, ScanOptions::default())
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
            },
            None => ScanResult {
                result_code: types::CL_CLEAN,
                virus_name: String::new(),
                bytes_scanned,
                arenas: Vec::new(),
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
        *self.engine.lock().unwrap() = engine;
        Ok(signatures_loaded)
    }

    /// Engine version string.
    pub fn version(&self) -> Option<String> {
        Some(format!("hydradragonclamav {}", env!("CARGO_PKG_VERSION")))
    }
}
