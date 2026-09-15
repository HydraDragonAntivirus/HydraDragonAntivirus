use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    TooSmall,
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidNtHeaders,
    InvalidOptionalHeader,
    InvalidSectionHeaders,
    RvaNotMapped(u32),
    OffsetNotMapped(u32),
    CorruptedData(&'static str),
    IoError(String),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::TooSmall => write!(f, "Data too small to be a valid PE"),
            PeError::InvalidDosSignature => write!(f, "Invalid DOS header signature (missing MZ)"),
            PeError::InvalidPeSignature => write!(f, "Invalid PE header signature (missing PE\0\0)"),
            PeError::InvalidNtHeaders => write!(f, "Invalid NT headers"),
            PeError::InvalidOptionalHeader => write!(f, "Invalid Optional Header"),
            PeError::InvalidSectionHeaders => write!(f, "Invalid Section Headers"),
            PeError::RvaNotMapped(rva) => write!(f, "RVA 0x{:X} is not mapped to any section", rva),
            PeError::OffsetNotMapped(off) => write!(f, "File offset 0x{:X} is not mapped to any section", off),
            PeError::CorruptedData(msg) => write!(f, "Corrupted PE data: {}", msg),
            PeError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for PeError {}

impl From<std::io::Error> for PeError {
    fn from(e: std::io::Error) -> Self {
        PeError::IoError(e.to_string())
    }
}
