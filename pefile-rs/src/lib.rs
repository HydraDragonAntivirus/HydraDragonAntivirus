//! # pefile-rs
//!
//! A pure-Rust, zero-dependency, comprehensive port of Ero Carrera's Python `pefile` library.
//! Designed for malware analysis, reverse engineering, PE parsing, and security tooling.

pub mod error;
pub mod headers;
pub mod sections;
pub mod directories;
pub mod utils;
pub mod pe;

pub use error::PeError;
pub use headers::{DosHeader, FileHeader, OptionalHeader, DataDirectory};
pub use sections::Section;
pub use directories::{
    ImportDirectory, ImportSymbol,
    ExportDirectory, ExportSymbol,
    ResourceDirectory, ResourceEntry, ResourceDataEntry,
    DebugEntry, TlsDirectory, LoadConfigDirectory, RelocationBlock,
};
pub use pe::PE;
