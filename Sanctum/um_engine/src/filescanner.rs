//! File scanner module
//!
//! This module provides functionality for scanning files and retrieving relevant
//! information about a file that the EDR may want to use in decision making.

use md5::{Digest, Md5};
use shared_no_std::constants::{IOC_LIST_LOCATION, IOC_URL};
use shared_std::file_scanner::{FileScannerState, MatchedIOC, ScanningLiveInfo};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant, UNIX_EPOCH},
};

use crate::utils::log::{Log, LogLevel};


const PARALLEL_SCAN_QUEUE_BOUND: usize = 4096;
const MAX_PARALLEL_SCAN_WORKERS: usize = 8;
const HASH_CACHE_LIMIT: usize = 16384;
const MAX_HASH_SCAN_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const HASH_READ_BUFFER_LIMIT: usize = 1024 * 1024; // 1 MiB per worker; keeps parallel scans memory-safe.

fn parallel_scan_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, MAX_PARALLEL_SCAN_WORKERS)
}

fn state_is_cancelled(state: &Arc<Mutex<FileScannerState>>) -> bool {
    *state.lock().unwrap() == FileScannerState::Cancelled
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileIdentity {
    normalized_path: String,
    size: u64,
    modified_unix_nanos: u128,
}

fn normalize_path_for_hash_cache(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn file_identity_for_hash_cache(path: &Path) -> Option<FileIdentity> {
    let metadata = path.metadata().ok()?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    Some(FileIdentity {
        normalized_path: normalize_path_for_hash_cache(path),
        size: metadata.len(),
        modified_unix_nanos,
    })
}

fn increment_files_scanned(files_scanned: &Arc<Mutex<u32>>) {
    let mut files_scanned = files_scanned.lock().unwrap();
    *files_scanned += 1;
}

fn scan_path_against_hashes(
    iocs: &BTreeSet<String>,
    state: &Arc<Mutex<FileScannerState>>,
    target: &PathBuf,
    files_scanned: &Arc<Mutex<u32>>,
    hash_cache: &Arc<Mutex<HashMap<FileIdentity, String>>>,
) -> Result<Option<(String, PathBuf)>, std::io::Error> {
    let Some(identity) = file_identity_for_hash_cache(target) else {
        return Ok(None);
    };

    if identity.size > MAX_HASH_SCAN_FILE_SIZE {
        return Ok(None);
    }

    if let Some(cached_hash) = hash_cache.lock().unwrap().get(&identity).cloned() {
        increment_files_scanned(files_scanned);
        if iocs.contains(cached_hash.as_str()) {
            return Ok(Some((cached_hash, target.clone())));
        }
        return Ok(None);
    }

    let file = File::open(target)?;
    let mut reader = BufReader::new(&file);

    let alloc_size = (identity.size as usize).clamp(1, HASH_READ_BUFFER_LIMIT);

    let mut hasher = Md5::new();
    let mut buf = vec![0u8; alloc_size];

    loop {
        if state_is_cancelled(state) {
            return Ok(None);
        }

        let count = reader.read(&mut buf)?;
        if count == 0 {
            break;
        }
        hasher.update(&buf[..count]);
    }

    let hash = hasher.finalize();
    let hash: String = hash.iter().map(|byte| format!("{:02X}", byte)).collect();

    increment_files_scanned(files_scanned);

    {
        let mut cache = hash_cache.lock().unwrap();
        if cache.len() >= HASH_CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(identity, hash.clone());
    }

    if iocs.contains(hash.as_str()) {
        return Ok(Some((hash, target.clone())));
    }

    Ok(None)
}

/// The FileScanner is the public interface into the module handling any static file scanning type capability.
/// This struct is public for visibility from lib.rs the core of um_engine, but it not intended to be accessed from the
/// Tauri application - for handling state (which tauri will need to interact with), see FileScannerState
pub struct FileScanner {
    // iocs:
    // Using a BTreeSet for the IOCs as it has the best time complexity for searching - Rust's implementation in the stdlib
    // I don't think is the best optimised BTree out there, but it will do the job for now. Not adding any IOC metadata to this
    // list of hashes (aka turning this into a BTreeMap) as it's a waste of memory and that metadata can be looked up with automations
    // either locally on disk or in the cloud.
    iocs: BTreeSet<String>,
    // state - The state of the scanner so we can lock it whilst scanning
    pub state: Arc<Mutex<FileScannerState>>,
    pub scanning_info: Arc<Mutex<ScanningLiveInfo>>,
    hash_cache: Arc<Mutex<HashMap<FileIdentity, String>>>,
    log: Log,
}

trait Sli {
    fn new() -> Self;
    fn reset(&mut self);
}

impl Sli for ScanningLiveInfo {
    fn new() -> Self {
        ScanningLiveInfo {
            num_files_scanned: 0,
            time_taken: Duration::new(0, 0),
            scan_results: Vec::<MatchedIOC>::new(),
        }
    }

    fn reset(&mut self) {
        self.num_files_scanned = 0;
        self.scan_results = Vec::new();
        self.time_taken = Duration::new(0, 0);
    }
}

impl FileScanner {
    /// Construct a new instance of the FileScanner with no parameters.
    pub async fn new() -> Result<Self, std::io::Error> {
        let log = Log::new();

        //
        // ingest latest IOC hash list
        //
        let mut bts: BTreeSet<String> = BTreeSet::new();
        let ioc_location = format!("{}\\{}", shared_no_std::constants::HYDRADRAGON_DIR, IOC_LIST_LOCATION);
        let ioc_dir = std::path::Path::new(&ioc_location).parent().unwrap().to_str().unwrap().to_string();

        let file = match File::open(&ioc_location) {
            Ok(f) => f,
            Err(e) => {
                log.log(
                    LogLevel::Warning,
                    format!("[-] IOC list not found, downloading to {}.", ioc_location).as_str(),
                );
                if e.kind() == io::ErrorKind::NotFound {
                    // Ensure directory exists
                    if let Err(err) = fs::create_dir_all(&ioc_dir) {
                        panic!("[-] Could not create directory for IOCs: {}. Error: {}", ioc_dir, err);
                    }

                    let file_data = reqwest::get(IOC_URL).await.unwrap().text().await.unwrap();
                    let mut f = File::create(&ioc_location).unwrap_or_else(|_| panic!(
                        "[-] Could not create file for IOCs. Loc: {}",
                        ioc_location
                    ));
                    f.write_all(file_data.as_bytes())
                        .expect("[-] Could not write data for IOCs");

                    f
                } else {
                    panic!("[-] Unknown error occurred when trying to ingest IOC files. {e}");
                }
            }
        };
        let lines = BufReader::new(file).lines();

        for line in lines.map_while(Result::ok) {
            bts.insert(line);
        }

        Ok(FileScanner {
            iocs: bts,
            state: Arc::new(Mutex::new(FileScannerState::Inactive)),
            scanning_info: Arc::new(Mutex::new(ScanningLiveInfo::new())),
            hash_cache: Arc::new(Mutex::new(HashMap::new())),
            log,
        })
    }

    pub fn scan_started(&self) {
        let mut lock = self.state.lock().unwrap();
        *lock = FileScannerState::Scanning;
        // reset the stats
        self.scanning_info.lock().unwrap().reset();
    }

    /// Checks whether a scan is in progress
    pub fn is_scanning(&self) -> bool {
        let lock = self.state.lock().unwrap();
        match *lock {
            FileScannerState::Scanning => true,
            FileScannerState::Finished => false,
            FileScannerState::FinishedWithError(_) => false,
            FileScannerState::Inactive => false,
            FileScannerState::Cancelled => false,
        }
    }

    /// Updates the internal is_scanning state to false
    pub fn end_scan(&self) {
        let mut lock = self.state.lock().unwrap();
        *lock = FileScannerState::Inactive;
    }

    /// Scan the file held by the FileScanner against a set of known bad hashes
    ///
    /// # Returns
    ///
    /// The function will return a tuple of Ok (String, PathBuf) if there were no IO errors, and the result of the Ok will be an Option of type
    /// (String, PathBuf). If the function returns None, then there was no hash match made for malware.
    ///
    /// If it returns the Some variant, the hash of the IOC will be returned for post-processing and decision making, as well as the file name / path as PathBuf.
    fn scan_file_against_hashes(
        &self,
        target: &PathBuf,
        files_scanned: &Arc<Mutex<u32>>,
    ) -> Result<Option<(String, PathBuf)>, std::io::Error> {
        scan_path_against_hashes(&self.iocs, &self.state, target, files_scanned, &self.hash_cache)
    }

    /// Public API entry point, scans from a root folder including all children, this can be used on a small
    /// scale for a folder scan, or used to initiate a system scan.
    pub fn begin_scan(&self, input_dirs: Vec<PathBuf>) -> Result<FileScannerState, io::Error> {
        let mut discovered_dirs: Vec<PathBuf> = Vec::new();

        // If the target is a directory, then add it back to the discovered dirs as that will be iterated
        // separate to the target - target is just used for scanning a single file.
        // This could be refactored at a later date so this check is done more inline below whilst still adhering
        // to how the functionality works.
        let mut target = PathBuf::new();
        if input_dirs.len() == 1 {
            target = input_dirs.clone().pop().unwrap();
            discovered_dirs.push(target.clone());
        } else {
            for t in input_dirs {
                if t.exists() && t.is_dir() {
                    discovered_dirs.push(t.clone());
                    target = t;
                }
            }
        }

        let stop_clock = Arc::new(Mutex::new(false));
        let clock_clone = Arc::clone(&stop_clock);
        let self_scanning_info_clone = Arc::clone(&self.scanning_info);

        let files_scanned: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let files_scanned_clone = Arc::clone(&files_scanned);
        let files_scanned_for_scanner = Arc::clone(&files_scanned);

        // timer in its own green thread
        thread::spawn(move || {
            let timer = Instant::now();

            loop {
                // first check if the task is cancelled
                if *clock_clone.lock().unwrap() {
                    break;
                }

                // not cancelled, so get the elapsed time
                let elapsed = timer.elapsed();
                let delta_files_scanned = {
                    let mut files_scanned_lock = files_scanned_clone.lock().unwrap();
                    let r = *files_scanned_lock; // get the result value
                    *files_scanned_lock = 0; // reset to 0
                    r
                };
                {
                    let mut lock = self_scanning_info_clone.lock().unwrap();
                    lock.time_taken = elapsed;
                    lock.num_files_scanned += delta_files_scanned as u128;
                }

                std::thread::sleep(Duration::from_millis(10));
            }
        });

        // if the target is a FILE, then scan only the 1 file
        if !target.is_dir() {
            let res = self.scan_file_against_hashes(&target, &files_scanned_for_scanner);
            match res {
                Ok(res) => {
                    if let Some(v) = res {
                        let mut lock = self.scanning_info.lock().unwrap();
                        lock.scan_results.push(MatchedIOC {
                            hash: v.0,
                            file: v.1,
                        });

                        // result will contain the matched IOC
                        *stop_clock.lock().unwrap() = true;
                        return Ok(FileScannerState::Finished);
                    }

                    *stop_clock.lock().unwrap() = true;
                    return Ok(FileScannerState::Finished);
                }
                Err(e) => {
                    *stop_clock.lock().unwrap() = true;

                    if e.kind() == io::ErrorKind::Uncategorized {
                        // results will be empty here
                        return Ok(FileScannerState::Cancelled);
                    }

                    return Err(e);
                }
            }
        }

        // otherwise, we are a directory so start this off with a bounded worker pool.
        // One producer walks directories; multiple workers hash files in parallel.
        let worker_count = parallel_scan_worker_count();
        let (file_tx, file_rx) = mpsc::sync_channel::<PathBuf>(PARALLEL_SCAN_QUEUE_BOUND);
        let file_rx = Arc::new(Mutex::new(file_rx));
        let worker_errors = Arc::new(Mutex::new(Vec::<String>::new()));

        thread::scope(|scope| {
            for worker_id in 0..worker_count {
                let file_rx = Arc::clone(&file_rx);
                let files_scanned = Arc::clone(&files_scanned_for_scanner);
                let scanning_info = Arc::clone(&self.scanning_info);
                let state = Arc::clone(&self.state);
                let worker_errors = Arc::clone(&worker_errors);
                let hash_cache = Arc::clone(&self.hash_cache);
                let iocs = &self.iocs;

                scope.spawn(move || loop {
                    let path = match file_rx.lock().unwrap().recv() {
                        Ok(path) => path,
                        Err(_) => break,
                    };

                    if state_is_cancelled(&state) {
                        break;
                    }

                    match scan_path_against_hashes(iocs, &state, &path, &files_scanned, &hash_cache) {
                        Ok(Some((hash, file))) => {
                            let mut lock = scanning_info.lock().unwrap();
                            lock.scan_results.push(MatchedIOC { hash, file });
                        }
                        Ok(None) => {}
                        Err(e) => {
                            let mut errors = worker_errors.lock().unwrap();
                            if errors.len() < 64 {
                                errors.push(format!(
                                    "worker {} failed to scan {}: {}",
                                    worker_id,
                                    path.display(),
                                    e
                                ));
                            }
                        }
                    }
                });
            }

            while !discovered_dirs.is_empty() {
                if state_is_cancelled(&self.state) {
                    break;
                }

                let Some(target) = discovered_dirs.pop() else {
                    continue;
                };

                let read_dir = match fs::read_dir(&target) {
                    Ok(read_dir) => read_dir,
                    Err(e) => {
                        self.log.log(
                            LogLevel::Warning,
                            &format!("[-] Error reading directory {}: {e}", target.display()),
                        );
                        continue;
                    }
                };

                for entry in read_dir {
                    if state_is_cancelled(&self.state) {
                        break;
                    }

                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            self.log
                                .log(LogLevel::Warning, &format!("[-] Error with entry, e: {e}"));
                            continue;
                        }
                    };

                    let path = entry.path();
                    if path.is_dir() {
                        discovered_dirs.push(path);
                        continue;
                    }

                    if let Err(e) = file_tx.send(path) {
                        self.log.log(
                            LogLevel::Warning,
                            &format!("[-] File scan worker queue closed: {e}"),
                        );
                        break;
                    }
                }
            }

            drop(file_tx);
        });

        for error in worker_errors.lock().unwrap().iter() {
            self.log
                .log(LogLevel::Warning, &format!("[-] Error scanning: {error}"));
        }

        if state_is_cancelled(&self.state) {
            *stop_clock.lock().unwrap() = true;
            return Err(io::Error::new(
                io::ErrorKind::Uncategorized,
                "User cancelled scan.",
            ));
        }

        *stop_clock.lock().unwrap() = true;

        Ok(FileScannerState::Finished)
    }

    /// Public entrypoint for scanning, taking in a target file / folder, and the scan type.
    ///
    /// This function ensures all state is accurate for whether a scan is in progress etc.
    ///
    /// # Returns
    ///
    /// The function will return the enum ScanResult which 'genericifies' the return type to give flexibility to
    /// allowing the function to conduct different types of scan. This will need checking in the calling function.
    pub fn start_scan(&self, target: Vec<PathBuf>) -> FileScannerState {
        // check whether a scan is active
        if self.is_scanning() {
            return FileScannerState::Scanning;
        }

        self.scan_started(); // update state

        // send the job for a scan
        let result = match self.begin_scan(target) {
            Ok(state) => state,
            Err(e) => FileScannerState::FinishedWithError(e.to_string()),
        };

        self.end_scan(); // update state

        result
    }

    /// Instructs the scanner to cancel its scan, returning information about the results
    pub fn cancel_scan(&self) -> Option<ScanningLiveInfo> {
        let mut lock = self.state.lock().unwrap();

        // check we are scanning, if not return
        if *lock == FileScannerState::Scanning {
            *lock = FileScannerState::Cancelled; // update state
            let sli = self.scanning_info.lock().unwrap();

            return Some(sli.clone());
        }

        None
    }

    /// Gets the state of the scanner
    pub fn get_state(&self) -> FileScannerState {
        let lock = self.state.lock().unwrap();
        lock.clone()
    }

    pub fn scanner_get_scan_data(&self) -> ScanningLiveInfo {
        self.scanning_info.lock().unwrap().clone()
    }
}
