// filetype/mod.rs — PE file parser.
//
// Ports TinyAntivirus's IPeFile / IPe64File interfaces and CPeFileParser
// implementation, using the `goblin` crate instead of hand-rolled Windows
// IMAGE_NT_HEADERS parsing.
//
// All address arithmetic (RVA↔VA↔FileOffset) faithfully ports the original.

pub mod pe_file;
pub use pe_file::{Pe32File, Pe64File, PeFile};
