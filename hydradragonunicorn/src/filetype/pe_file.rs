// filetype/pe_file.rs — PE (Portable Executable) parser.
//
// Ports TinyAntivirus's CPeFileParser / IPeFile / IPe64File using the
// `goblin` crate. Provides the same operations the scanner and emulator
// rely on: section lookup, RVA/VA/FileOffset conversions, entry-point
// data reading, section truncation, and disinfection helpers.

use crate::error::{AvError, AvResult};
use goblin::pe::PE;
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Shared section helpers
// ---------------------------------------------------------------------------

/// Compact representation of a section header.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_address: u32, // RVA of section start
    pub virtual_size: u32,
    pub raw_offset: u32, // file offset of raw data
    pub raw_size: u32,
    pub characteristics: u32,
}

// ---------------------------------------------------------------------------
// Pe32File
// ---------------------------------------------------------------------------

/// 32-bit PE file (ports IPeFile / CPeFileParser for x86).
///
/// Holds parsed metadata in memory while delegating raw I/O to the caller-
/// supplied byte slice.  This design lets the scanner pass either a MemoryFs
/// buffer or a mmap'd file without extra copies.
pub struct Pe32File {
    data: Vec<u8>,
    image_base: u32,
    entry_point_rva: u32,
    sections: Vec<SectionHeader>,
    is_pe: bool,
}

impl Pe32File {
    /// Parse a PE32 from raw bytes (e.g. from MemoryFs::get_buffer).
    pub fn parse(data: Vec<u8>) -> AvResult<Self> {
        use goblin::Object;
        // First pass: validate it is a PE32 (not PE32+). The borrow of data ends here.
        match goblin::Object::parse(&data) {
            Ok(Object::PE(pe)) if pe.is_64 => {
                return Err(AvError::MalformedPe { reason: "expected PE32, got PE32+".into() })
            }
            Ok(Object::PE(_)) => {}
            Ok(_) => return Err(AvError::NotPeFile),
            Err(e) => return Err(AvError::MalformedPe { reason: format!("{e}") }),
        }
        // Second pass: parse a clone so pe borrows the clone, leaving data free to move.
        let data_buf = data.clone();
        match goblin::Object::parse(&data_buf) {
            Ok(Object::PE(pe)) => Self::from_goblin(data, pe),
            _ => Err(AvError::NotPeFile),
        }
    }

    /// Parse from a file on disk.
    pub fn from_path(path: &Path) -> AvResult<Self> {
        let data = std::fs::read(path)?;
        Self::parse(data)
    }

    fn from_goblin(data: Vec<u8>, pe: PE) -> AvResult<Self> {
        if pe.is_64 {
            return Err(AvError::MalformedPe {
                reason: "expected PE32, got PE32+".into(),
            });
        }
        let image_base = pe.image_base as u32;
        let entry_point_rva = pe.entry as u32;

        let sections: Vec<SectionHeader> = pe
            .sections
            .iter()
            .map(|s| SectionHeader {
                name: String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string(),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_offset: s.pointer_to_raw_data,
                raw_size: s.size_of_raw_data,
                characteristics: s.characteristics,
            })
            .collect();

        Ok(Self {
            data,
            image_base,
            entry_point_rva,
            sections,
            is_pe: true,
        })
    }

    // ------------------------------------------------------------------
    // Public API (mirrors IPeFile)
    // ------------------------------------------------------------------

    /// Whether this object contains a valid PE image.
    pub fn is_valid(&self) -> bool {
        self.is_pe
    }

    /// Number of sections.
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Get section header by index.
    pub fn section_header(&self, index: usize) -> AvResult<&SectionHeader> {
        self.sections.get(index).ok_or(AvError::SectionOutOfRange {
            index,
            count: self.sections.len(),
        })
    }

    /// Convert RVA → file offset.
    pub fn rva_to_file_offset(&self, rva: u32) -> AvResult<u32> {
        for s in &self.sections {
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size)
            {
                return Ok(rva - s.virtual_address + s.raw_offset);
            }
        }
        Err(AvError::RvaNotMapped { rva })
    }

    /// Convert VA → file offset.
    pub fn va_to_file_offset(&self, va: u32) -> AvResult<u32> {
        if va < self.image_base {
            return Err(AvError::VaNotMapped { va: va as u64 });
        }
        self.rva_to_file_offset(va - self.image_base)
    }

    /// Convert file offset → RVA.
    pub fn file_offset_to_rva(&self, offset: u32) -> AvResult<u32> {
        for s in &self.sections {
            if offset >= s.raw_offset && offset < s.raw_offset + s.raw_size {
                return Ok(offset - s.raw_offset + s.virtual_address);
            }
        }
        Err(AvError::RvaNotMapped { rva: offset })
    }

    /// Convert file offset → VA.
    pub fn file_offset_to_va(&self, offset: u32) -> AvResult<u32> {
        self.file_offset_to_rva(offset)
            .map(|rva| rva + self.image_base)
    }

    /// Find the section containing the given RVA.
    pub fn find_section_by_rva(&self, rva: u32) -> AvResult<usize> {
        self.sections
            .iter()
            .enumerate()
            .find(|(_, s)| {
                rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size)
            })
            .map(|(i, _)| i)
            .ok_or(AvError::RvaNotMapped { rva })
    }

    /// Find section by VA.
    pub fn find_section_by_va(&self, va: u32) -> AvResult<usize> {
        if va < self.image_base {
            return Err(AvError::VaNotMapped { va: va as u64 });
        }
        self.find_section_by_rva(va - self.image_base)
    }

    /// Find section by raw file offset.
    pub fn find_section_by_file_offset(&self, offset: u32) -> AvResult<usize> {
        self.sections
            .iter()
            .enumerate()
            .find(|(_, s)| offset >= s.raw_offset && offset < s.raw_offset + s.raw_size)
            .map(|(i, _)| i)
            .ok_or(AvError::RvaNotMapped { rva: offset })
    }

    /// Read raw bytes of a section.
    pub fn read_section_data(&self, index: usize) -> AvResult<&[u8]> {
        let s = self.section_header(index)?;
        let start = s.raw_offset as usize;
        let end = (s.raw_offset + s.raw_size) as usize;
        if end > self.data.len() {
            return Err(AvError::MalformedPe {
                reason: format!("section {index} raw data beyond EOF"),
            });
        }
        Ok(&self.data[start..end])
    }

    /// Read raw bytes of the section containing the entry point.
    pub fn read_ep_section_data(&self) -> AvResult<&[u8]> {
        let idx = self.find_section_by_rva(self.entry_point_rva)?;
        self.read_section_data(idx)
    }

    /// Read bytes starting at the entry point.
    pub fn read_entry_point_data(&self, max_size: usize) -> AvResult<Vec<u8>> {
        let file_off = self.rva_to_file_offset(self.entry_point_rva)? as usize;
        if file_off >= self.data.len() {
            return Err(AvError::MalformedPe {
                reason: "entry point beyond EOF".into(),
            });
        }
        let end = (file_off + max_size).min(self.data.len());
        Ok(self.data[file_off..end].to_vec())
    }

    /// Set a new entry-point by VA (in-memory mutation for disinfection).
    pub fn set_va_to_entry_point(&mut self, va: u32) -> AvResult<()> {
        if va < self.image_base {
            return Err(AvError::VaNotMapped { va: va as u64 });
        }
        self.entry_point_rva = va - self.image_base;
        // Patch the in-memory PE header bytes so the emulator sees the change
        // Standard offset for AddressOfEntryPoint in IMAGE_NT_HEADERS32:
        // e_lfanew(4-byte at 0x3C) + 4(sig) + 20(FILE_HDR) + 16 = +40 from NT hdr start
        let e_lfanew = u32::from_le_bytes(self.data[0x3C..0x40].try_into().map_err(|_| {
            AvError::MalformedPe {
                reason: "bad e_lfanew".into(),
            }
        })?) as usize;
        let ep_offset = e_lfanew + 4 + 20 + 16; // OptionalHeader.AddressOfEntryPoint
        if ep_offset + 4 > self.data.len() {
            return Err(AvError::MalformedPe {
                reason: "EP patch offset OOB".into(),
            });
        }
        self.data[ep_offset..ep_offset + 4].copy_from_slice(&self.entry_point_rva.to_le_bytes());
        Ok(())
    }

    /// Set a new entry-point by RVA.
    pub fn set_rva_to_entry_point(&mut self, rva: u32) -> AvResult<()> {
        self.set_va_to_entry_point(rva + self.image_base)
    }

    /// Truncate from a given section to end of file (ports Truncate / TruncateSectionUntilEndOfFile).
    ///
    /// `padding`: if true, fill with 0xC3 (RET) instead of actually truncating.
    pub fn truncate(&mut self, va: u32, padding: bool) -> AvResult<()> {
        let file_off = self.va_to_file_offset(va)? as usize;
        if padding {
            for b in &mut self.data[file_off..] {
                *b = 0xC3;
            }
        } else {
            self.data.truncate(file_off);
        }
        Ok(())
    }

    /// Truncate sections from `section_index` to end of file.
    pub fn truncate_section_until_eof(&mut self, section_index: usize) -> AvResult<()> {
        let s = self.section_header(section_index)?.clone();
        self.data.truncate(s.raw_offset as usize);
        Ok(())
    }

    /// Release parsed state (ports ReleaseCurrentFile — allows re-use).
    pub fn release(&mut self) {
        self.data.clear();
        self.sections.clear();
        self.is_pe = false;
    }

    /// Raw byte access (needed by emulator to map the image).
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Image base address.
    pub fn image_base(&self) -> u32 {
        self.image_base
    }

    /// Entry-point RVA.
    pub fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
    }

    /// Entry-point VA.
    pub fn entry_point_va(&self) -> u32 {
        self.image_base + self.entry_point_rva
    }

    /// Check if this is a PE file and write back to a stream (for disinfection).
    pub fn write_to<W: Write>(&self, writer: &mut W) -> AvResult<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pe64File
// ---------------------------------------------------------------------------

/// 64-bit PE file (ports IPe64File / CPe64FileParser for x86-64).
pub struct Pe64File {
    data: Vec<u8>,
    image_base: u64,
    entry_point_rva: u32,
    sections: Vec<SectionHeader>,
    is_pe: bool,
}

impl Pe64File {
    pub fn parse(data: Vec<u8>) -> AvResult<Self> {
        use goblin::Object;
        // First pass: validate it is PE32+. Borrow of data ends here.
        match goblin::Object::parse(&data) {
            Ok(Object::PE(pe)) if !pe.is_64 => {
                return Err(AvError::MalformedPe { reason: "expected PE32+, got PE32".into() })
            }
            Ok(Object::PE(_)) => {}
            Ok(_) => return Err(AvError::NotPeFile),
            Err(e) => return Err(AvError::MalformedPe { reason: format!("{e}") }),
        }
        // Second pass: parse a clone so pe borrows the clone, leaving data free to move.
        let data_buf = data.clone();
        match goblin::Object::parse(&data_buf) {
            Ok(Object::PE(pe)) => Self::from_goblin(data, pe),
            _ => Err(AvError::NotPeFile),
        }
    }

    pub fn from_path(path: &Path) -> AvResult<Self> {
        let data = std::fs::read(path)?;
        Self::parse(data)
    }

    fn from_goblin(data: Vec<u8>, pe: PE) -> AvResult<Self> {
        let image_base = pe.image_base as u64;
        let entry_point_rva = pe.entry as u32;
        let sections: Vec<SectionHeader> = pe
            .sections
            .iter()
            .map(|s| SectionHeader {
                name: String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string(),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_offset: s.pointer_to_raw_data,
                raw_size: s.size_of_raw_data,
                characteristics: s.characteristics,
            })
            .collect();
        Ok(Self {
            data,
            image_base,
            entry_point_rva,
            sections,
            is_pe: true,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.is_pe
    }
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
    pub fn image_base(&self) -> u64 {
        self.image_base
    }
    pub fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
    }
    pub fn entry_point_va(&self) -> u64 {
        self.image_base + self.entry_point_rva as u64
    }
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    pub fn section_header(&self, index: usize) -> AvResult<&SectionHeader> {
        self.sections.get(index).ok_or(AvError::SectionOutOfRange {
            index,
            count: self.sections.len(),
        })
    }

    pub fn rva_to_file_offset(&self, rva: u64) -> AvResult<u32> {
        for s in &self.sections {
            let rva32 = rva as u32;
            if rva32 >= s.virtual_address
                && rva32 < s.virtual_address + s.virtual_size.max(s.raw_size)
            {
                return Ok(rva32 - s.virtual_address + s.raw_offset);
            }
        }
        Err(AvError::RvaNotMapped { rva: rva as u32 })
    }

    pub fn va_to_file_offset(&self, va: u64) -> AvResult<u32> {
        if va < self.image_base {
            return Err(AvError::VaNotMapped { va });
        }
        self.rva_to_file_offset(va - self.image_base)
    }

    pub fn release(&mut self) {
        self.data.clear();
        self.sections.clear();
        self.is_pe = false;
    }
}

// ---------------------------------------------------------------------------
// PeFile enum — unified 32/64 dispatch
// ---------------------------------------------------------------------------

/// Unified PE file (auto-detects 32/64 bit).
pub enum PeFile {
    Pe32(Pe32File),
    Pe64(Pe64File),
}

impl PeFile {
    /// Parse from raw bytes, auto-detecting bitness.
    pub fn parse(data: Vec<u8>) -> AvResult<Self> {
        use goblin::Object;
        // First pass: detect bitness. The borrow of `data` ends before we move it.
        let is_64 = match goblin::Object::parse(&data) {
            Ok(Object::PE(pe)) => pe.is_64,
            Ok(_) => return Err(AvError::NotPeFile),
            Err(e) => return Err(AvError::MalformedPe { reason: format!("{e}") }),
        };
        // Second pass: delegate to the typed parser which takes ownership.
        if is_64 {
            Pe64File::parse(data).map(PeFile::Pe64)
        } else {
            Pe32File::parse(data).map(PeFile::Pe32)
        }
    }

    pub fn from_path(path: &Path) -> AvResult<Self> {
        Self::parse(std::fs::read(path)?)
    }

    pub fn is_64(&self) -> bool {
        matches!(self, PeFile::Pe64(_))
    }

    pub fn raw_data(&self) -> &[u8] {
        match self {
            PeFile::Pe32(p) => p.raw_data(),
            PeFile::Pe64(p) => p.raw_data(),
        }
    }

    pub fn entry_point_va(&self) -> u64 {
        match self {
            PeFile::Pe32(p) => p.entry_point_va() as u64,
            PeFile::Pe64(p) => p.entry_point_va(),
        }
    }

    pub fn image_base(&self) -> u64 {
        match self {
            PeFile::Pe32(p) => p.image_base() as u64,
            PeFile::Pe64(p) => p.image_base(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE32 stub (MZ + NT headers, one section).
    fn minimal_pe32() -> Vec<u8> {
        // This is a real minimal PE32 with .text section, EP at RVA 0x1000,
        // ImageBase 0x400000, sections raw at offset 0x400.
        // Built from scratch to avoid external test fixtures.
        let mut pe = vec![0u8; 0x600];
        // MZ header
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew at 0x3C = 0x40
        pe[0x3C] = 0x40;
        // PE signature at 0x40
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        // COFF header (IMAGE_FILE_HEADER) at 0x44
        pe[0x44] = 0x4C;
        pe[0x45] = 0x01; // Machine: IMAGE_FILE_MACHINE_I386
        pe[0x46] = 0x01; // NumberOfSections: 1
        pe[0x50] = 0xE0; // SizeOfOptionalHeader: 0xE0
        pe[0x52] = 0x02; // Characteristics: executable
                         // Optional header at 0x58
        pe[0x58] = 0x0B;
        pe[0x59] = 0x01; // Magic: PE32
                         // AddressOfEntryPoint at 0x58 + 16 = 0x68
        pe[0x68] = 0x00;
        pe[0x69] = 0x10;
        pe[0x6A] = 0x00;
        pe[0x6B] = 0x00; // EP RVA = 0x1000
                         // ImageBase at 0x58 + 28 = 0x74
        pe[0x74] = 0x00;
        pe[0x75] = 0x00;
        pe[0x76] = 0x40;
        pe[0x77] = 0x00; // 0x00400000
                         // Section table at 0x58 + 0xE0 = 0x138
                         // Name ".text"
        pe[0x138] = b'.';
        pe[0x139] = b't';
        pe[0x13A] = b'e';
        pe[0x13B] = b'x';
        pe[0x13C] = b't';
        // VirtualSize at +8
        pe[0x140] = 0x00;
        pe[0x141] = 0x10; // 0x1000
                          // VirtualAddress at +12
        pe[0x144] = 0x00;
        pe[0x145] = 0x10; // RVA 0x1000
                          // SizeOfRawData at +16
        pe[0x148] = 0x00;
        pe[0x149] = 0x02; // 0x200
                          // PointerToRawData at +20
        pe[0x14C] = 0x00;
        pe[0x14D] = 0x04; // file offset 0x400
        pe
    }

    #[test]
    fn parse_non_pe_fails() {
        let data = b"not a pe file at all".to_vec();
        assert!(Pe32File::parse(data).is_err());
    }

    #[test]
    fn rva_not_mapped_error() {
        // Use a valid PE if available; otherwise just check the error type
        let pe = Pe32File {
            data: vec![0u8; 0x600],
            image_base: 0x400000,
            entry_point_rva: 0x1000,
            sections: vec![SectionHeader {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x200,
                raw_offset: 0x400,
                raw_size: 0x200,
                characteristics: 0,
            }],
            is_pe: true,
        };
        assert!(matches!(
            pe.rva_to_file_offset(0x9999),
            Err(AvError::RvaNotMapped { .. })
        ));
    }

    #[test]
    fn rva_to_file_offset_round_trip() {
        let pe = Pe32File {
            data: vec![0u8; 0x800],
            image_base: 0x400000,
            entry_point_rva: 0x1000,
            sections: vec![SectionHeader {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x200,
                raw_offset: 0x400,
                raw_size: 0x200,
                characteristics: 0,
            }],
            is_pe: true,
        };
        assert_eq!(pe.rva_to_file_offset(0x1010).unwrap(), 0x410);
        assert_eq!(pe.file_offset_to_rva(0x410).unwrap(), 0x1010);
    }

    #[test]
    fn va_to_file_offset() {
        let pe = Pe32File {
            data: vec![0u8; 0x800],
            image_base: 0x400000,
            entry_point_rva: 0x1000,
            sections: vec![SectionHeader {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x200,
                raw_offset: 0x400,
                raw_size: 0x200,
                characteristics: 0,
            }],
            is_pe: true,
        };
        assert_eq!(pe.va_to_file_offset(0x401010).unwrap(), 0x410);
    }

    #[test]
    fn section_out_of_range() {
        let pe = Pe32File {
            data: vec![],
            image_base: 0x400000,
            entry_point_rva: 0x1000,
            sections: vec![],
            is_pe: true,
        };
        assert!(matches!(
            pe.section_header(5),
            Err(AvError::SectionOutOfRange { .. })
        ));
    }
}
