// filetype/mod.rs — Pure-Rust PE file parser.
//
// Ports TinyAntivirus's IPeFile / IPe64File interfaces and CPeFileParser
// implementation using zero-dependency pure-Rust PE parsing.
//
// All address arithmetic (RVA↔VA↔FileOffset) faithfully ports the original.

pub mod pe_file;
pub use pe_file::{Pe32File, Pe64File, PeFile};
