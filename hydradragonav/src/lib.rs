#![cfg(windows)]

pub mod bloom_filter;
pub mod clamjuice;
pub mod detectiteasy;
pub mod ffi;
pub mod hash_scanner;
pub mod ml;
pub mod pipeline;
pub mod registry_scanner;
pub mod scanner;
pub mod types;
pub mod verdict;

pub use scanner::{run_freshclam_dll, LogCallback, Scanner};
pub use types::{Error, ScanResult as ClamavScanResult, CL_CLEAN, CL_VIRUS};
pub use verdict::{EngineResult, ScanResult, Verdict};
