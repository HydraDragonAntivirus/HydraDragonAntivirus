//! # nuitka-extractor
//!
//! Extracts the embedded payload of a [Nuitka](https://nuitka.net/) onefile
//! executable into memory without touching the filesystem, so callers (e.g.
//! HydraDragonAntivirus) can scan each file's bytes directly.
//!
//! ## Quick start
//!
//! ```no_run
//! use nuitka_extractor::NuitkaExtractor;
//!
//! let extractor = NuitkaExtractor::open("target.exe")?;
//! for entry in extractor.extract_to_memory()? {
//!     let entry = entry?;
//!     println!("scanning {} ({} bytes)", entry.name, entry.data.len());
//!     // pass entry.data to your scanner here
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::{
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use pelite::{
    resources::{Entry, Name},
    FileMap, PeFile, Wrap,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A single file extracted from a Nuitka onefile executable, held entirely
/// in memory so the caller can scan the bytes without disk I/O.
#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    /// The original path stored inside the Nuitka archive (normalised to
    /// forward slashes, `..` components replaced with `__`).
    pub name: String,
    /// Raw file contents.
    pub data: Vec<u8>,
}

/// Detected executable format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Elf,
    Pe,
}

/// Compression used by the Nuitka payload stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
}

// ── Core extractor ────────────────────────────────────────────────────────────

/// Parses and extracts a Nuitka onefile executable.
///
/// Construction validates the file headers and locates the embedded payload.
/// Call [`extract_to_memory`](NuitkaExtractor::extract_to_memory) to iterate
/// over every embedded file as an in-memory [`ExtractedEntry`].
pub struct NuitkaExtractor {
    path: PathBuf,
    /// Detected format of the outer executable.
    pub kind: FileKind,
    /// Compression applied to the Nuitka payload stream.
    pub compression: Compression,
    /// File offset of the first byte after the 3-byte magic ("KAX"/"KAY").
    stream_start: u64,
    /// Total payload size in bytes (excluding the 8-byte size trailer and the
    /// 3-byte magic).
    pub payload_size: u64,
}

impl NuitkaExtractor {
    /// Open and validate a Nuitka onefile executable at `path`.
    ///
    /// Returns an error if the file cannot be read, is not a supported format,
    /// or does not contain a recognisable Nuitka payload.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = std::fs::File::open(&path)
            .with_context(|| format!("Couldn't open {}", path.display()))?;

        // ── Detect outer format ───────────────────────────────────────────────
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic)
            .context("File too small to read magic bytes")?;

        let kind = if magic[0] == 0x4D && magic[1] == 0x5A {
            FileKind::Pe
        } else if magic == [0x7F, 0x45, 0x4C, 0x46] {
            FileKind::Elf
        } else {
            bail!("Unsupported file type (magic: {:02X?})", &magic[..4]);
        };

        // ── Locate the 8-byte payload-size trailer ────────────────────────────
        let size_field_pos: u64 = if kind == FileKind::Pe {
            let rcdata_end =
                locate_rcdata_end(&path).context("Failed to locate Nuitka RCDATA in PE")?;
            rcdata_end
                .checked_sub(8)
                .context("rcdata_end < 8 — file appears malformed")?
        } else {
            let len = f.seek(SeekFrom::End(0))?;
            len.checked_sub(8)
                .context("ELF too small to contain a Nuitka payload")?
        };

        f.seek(SeekFrom::Start(size_field_pos))?;
        let mut size_buf = [0u8; 8];
        f.read_exact(&mut size_buf)?;
        let payload_size = u64::from_le_bytes(size_buf);

        let payload_start = size_field_pos
            .checked_sub(payload_size)
            .context("Payload size exceeds file position — file is malformed")?;

        // ── Validate Nuitka magic ─────────────────────────────────────────────
        f.seek(SeekFrom::Start(payload_start))?;
        let mut nk_magic = [0u8; 3];
        f.read_exact(&mut nk_magic)?;

        let compression = match &nk_magic {
            b"KAX" => Compression::None,
            b"KAY" => Compression::Zstd,
            _ => bail!("Nuitka magic header mismatch (got {:02X?})", nk_magic),
        };

        Ok(Self {
            path,
            kind,
            compression,
            stream_start: payload_start + 3,
            payload_size,
        })
    }

    /// Extract every file from the Nuitka payload into memory.
    ///
    /// Returns a [`Vec`] of results, one per embedded file.  Individual entry
    /// errors are surfaced as `Err` items so callers can choose to skip or
    /// abort on a per-file basis.
    ///
    /// For very large payloads consider [`iter_entries`](Self::iter_entries)
    /// which yields entries one at a time without buffering everything at once.
    pub fn extract_to_memory(&self) -> Result<Vec<Result<ExtractedEntry>>> {
        self.iter_entries().map(|iter| iter.collect())
    }

    /// Iterate over embedded files one at a time, yielding each as an
    /// [`ExtractedEntry`] without pre-loading the whole payload.
    ///
    /// This is the preferred API when integrating with a streaming scanner.
    pub fn iter_entries(&self) -> Result<impl Iterator<Item = Result<ExtractedEntry>> + '_> {
        let f = std::fs::File::open(&self.path)?;
        let mut reader = BufReader::new(f);
        reader.seek(SeekFrom::Start(self.stream_start))?;

        let iter: Box<dyn Iterator<Item = Result<ExtractedEntry>>> =
            match self.compression {
                Compression::None => Box::new(EntryIter::new(reader, self.kind)),
                Compression::Zstd => {
                    let dec = zstd::stream::read::Decoder::new(reader)
                        .context("Failed to initialise zstd decoder")?;
                    Box::new(EntryIter::new(BufReader::new(dec), self.kind))
                }
            };

        Ok(iter)
    }

    /// Extract all embedded files and return only their raw byte contents,
    /// discarding filenames.  Convenience wrapper for scan-everything use cases.
    pub fn extract_all_bytes(&self) -> Result<Vec<Vec<u8>>> {
        self.iter_entries()?
            .map(|r| r.map(|e| e.data))
            .collect()
    }

    /// Path of the source executable.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ── Lazy iterator ─────────────────────────────────────────────────────────────

struct EntryIter<R: Read> {
    stream: R,
    kind: FileKind,
    done: bool,
}

impl<R: Read> EntryIter<R> {
    fn new(stream: R, kind: FileKind) -> Self {
        Self {
            stream,
            kind,
            done: false,
        }
    }

    fn next_entry(&mut self) -> Result<Option<ExtractedEntry>> {
        // ── Filename ──────────────────────────────────────────────────────────
        let name = match read_filename(&mut self.stream, self.kind)? {
            Some(n) => n,
            None => return Ok(None), // end-of-archive sentinel
        };

        // ── ELF per-file flags byte ───────────────────────────────────────────
        if self.kind == FileKind::Elf {
            let mut _flags = [0u8; 1];
            self.stream.read_exact(&mut _flags)?;
        }

        // ── File size (8 bytes, little-endian) ────────────────────────────────
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf)?;
        let file_size = u64::from_le_bytes(size_buf);

        // ── Extra header: CRC32 or ArchiveSize (4 bytes) ─────────────────────
        // Added in newer Nuitka versions; we skip it.
        // References:
        //   https://github.com/Nuitka/Nuitka/blob/develop/nuitka/build/static_src/OnefileBootstrap.c
        //   https://github.com/Nuitka/Nuitka/blob/develop/nuitka/tools/onefile_compressor/OnefileCompressor.py
        let mut _extra = [0u8; 4];
        self.stream.read_exact(&mut _extra)?;

        // ── Read file data into memory ────────────────────────────────────────
        let mut data = Vec::with_capacity(file_size.min(64 * 1024 * 1024) as usize);
        self.stream
            .by_ref()
            .take(file_size)
            .read_to_end(&mut data)
            .with_context(|| format!("Failed to read data for '{name}'"))?;

        if data.len() as u64 != file_size {
            bail!(
                "Truncated payload for '{}': expected {file_size} bytes, got {}",
                name,
                data.len()
            );
        }

        // ── Sanitise path ─────────────────────────────────────────────────────
        let name = name.replace('\\', "/").replace("..", "__");
        let name = name.trim_start_matches('/').to_owned();

        Ok(Some(ExtractedEntry { name, data }))
    }
}

impl<R: Read> Iterator for EntryIter<R> {
    type Item = Result<ExtractedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true; // stream is in an unknown state; stop iterating
                Some(Err(e))
            }
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Read a null-terminated filename from `stream`.
///
/// * PE payloads — UTF-16 LE, terminated by a zero code unit (2 bytes of 0x00).
/// * ELF payloads — UTF-8, terminated by a single 0x00 byte.
///
/// Returns `None` when an empty name is encountered (end-of-archive signal).
fn read_filename<R: Read>(stream: &mut R, kind: FileKind) -> Result<Option<String>> {
    if kind == FileKind::Pe {
        let mut units = Vec::<u16>::new();
        let mut buf = [0u8; 2];
        loop {
            stream.read_exact(&mut buf)?;
            let unit = u16::from_le_bytes(buf);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        if units.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            String::from_utf16(&units).context("Invalid UTF-16LE filename in PE payload")?,
        ))
    } else {
        let mut bytes = Vec::<u8>::new();
        let mut buf = [0u8; 1];
        loop {
            stream.read_exact(&mut buf)?;
            if buf[0] == 0 {
                break;
            }
            bytes.push(buf[0]);
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            String::from_utf8(bytes).context("Invalid UTF-8 filename in ELF payload")?,
        ))
    }
}

/// Return the file offset immediately past the end of the Nuitka RCDATA blob.
///
/// Nuitka stores its onefile payload in the PE resource tree at:
///   RCDATA (type id = 10) → id = 27 → single language leaf
///
/// Reference:
///   <https://github.com/Nuitka/Nuitka/blob/b4ae0b6701533c22be732837db49ce5b5f5a90ce/nuitka/build/static_src/OnefileBootstrap.c#L216>
fn locate_rcdata_end(path: &Path) -> Result<u64> {
    let map = FileMap::open(path).context("FileMap::open failed")?;
    let pe = PeFile::from_bytes(map.as_ref()).context("Not a valid PE file")?;

    let resources = match &pe {
        Wrap::T64(p) => {
            use pelite::pe64::Pe as _;
            p.resources().context("PE has no resource directory")?
        }
        Wrap::T32(p) => {
            use pelite::pe32::Pe as _;
            p.resources().context("PE has no resource directory")?
        }
    };

    let rcdata = resources
        .root()
        .context("Resource root is empty")?
        .get_dir(Name::Id(10))
        .context("RCDATA directory not found in PE resources")?;

    let id27 = rcdata
        .get_dir(Name::Id(27))
        .context("RCDATA/27 sub-directory not found")?;

    let mut iter = id27.entries();
    let leaf = iter.next().context("RCDATA/27 is empty")?;
    if iter.next().is_some() {
        bail!("RCDATA/27 contains more than one leaf; unexpected layout");
    }

    let data = match leaf.entry().context("Failed to read RCDATA/27 leaf")? {
        Entry::DataEntry(d) => d,
        Entry::Directory(_) => bail!("RCDATA/27 leaf is a directory, expected data"),
    };

    let rva = data.image().OffsetToData;
    let size = data.image().Size;

    let file_off = match &pe {
        Wrap::T64(p) => {
            use pelite::pe64::Pe as _;
            p.rva_to_file_offset(rva)
                .context("RVA→file-offset failed (PE64)")?
        }
        Wrap::T32(p) => {
            use pelite::pe32::Pe as _;
            p.rva_to_file_offset(rva)
                .context("RVA→file-offset failed (PE32)")?
        }
    };

    Ok(file_off as u64 + size as u64)
}

// ── In-memory extraction (no filesystem required) ─────────────────────────────

/// Extract a Nuitka onefile executable from an in-memory byte slice.
///
/// Equivalent to [`NuitkaExtractor::open`] + [`extract_to_memory`](NuitkaExtractor::extract_to_memory)
/// but works entirely from a `&[u8]` — useful when the executable was itself
/// read into memory or received over a network before scanning.
pub fn extract_from_bytes(bytes: &[u8]) -> Result<Vec<ExtractedEntry>> {
    // ── Detect format ─────────────────────────────────────────────────────────
    let kind = if bytes.len() >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A {
        FileKind::Pe
    } else if bytes.len() >= 4 && bytes[..4] == [0x7F, 0x45, 0x4C, 0x46] {
        FileKind::Elf
    } else {
        bail!("Unsupported file type (magic: {:02X?})", &bytes[..4.min(bytes.len())]);
    };

    // ── Locate payload-size trailer ───────────────────────────────────────────
    let size_field_pos: usize = if kind == FileKind::Pe {
        let rcdata_end = locate_rcdata_end_from_slice(bytes)?;
        rcdata_end
            .checked_sub(8)
            .context("rcdata_end < 8 — malformed PE")? as usize
    } else {
        bytes
            .len()
            .checked_sub(8)
            .context("ELF slice too small to contain a Nuitka payload")?
    };

    let payload_size =
        u64::from_le_bytes(bytes[size_field_pos..size_field_pos + 8].try_into().unwrap());

    let payload_start = (size_field_pos as u64)
        .checked_sub(payload_size)
        .context("Payload size exceeds slice position — malformed")? as usize;

    let nk_magic = &bytes[payload_start..payload_start + 3];
    let compression = match nk_magic {
        b"KAX" => Compression::None,
        b"KAY" => Compression::Zstd,
        _ => bail!("Nuitka magic header mismatch (got {:02X?})", nk_magic),
    };

    let stream_start = payload_start + 3;
    let payload_bytes = &bytes[stream_start..size_field_pos];

    // ── Decompress and iterate ────────────────────────────────────────────────
    let mut entries = Vec::new();
    match compression {
        Compression::None => {
            let mut cursor = Cursor::new(payload_bytes);
            let iter = EntryIter::new(&mut cursor, kind);
            for result in iter {
                entries.push(result?);
            }
        }
        Compression::Zstd => {
            let cursor = Cursor::new(payload_bytes);
            let dec =
                zstd::stream::read::Decoder::new(cursor).context("Failed to init zstd decoder")?;
            let iter = EntryIter::new(BufReader::new(dec), kind);
            for result in iter {
                entries.push(result?);
            }
        }
    }

    Ok(entries)
}

/// [`locate_rcdata_end`] operating on a byte slice instead of a file path.
fn locate_rcdata_end_from_slice(bytes: &[u8]) -> Result<u64> {
    let pe = PeFile::from_bytes(bytes).context("Not a valid PE file")?;

    let resources = match &pe {
        Wrap::T64(p) => {
            use pelite::pe64::Pe as _;
            p.resources().context("PE has no resource directory")?
        }
        Wrap::T32(p) => {
            use pelite::pe32::Pe as _;
            p.resources().context("PE has no resource directory")?
        }
    };

    let rcdata = resources
        .root()
        .context("Resource root is empty")?
        .get_dir(Name::Id(10))
        .context("RCDATA directory not found")?;

    let id27 = rcdata
        .get_dir(Name::Id(27))
        .context("RCDATA/27 sub-directory not found")?;

    let mut iter = id27.entries();
    let leaf = iter.next().context("RCDATA/27 is empty")?;
    if iter.next().is_some() {
        bail!("RCDATA/27 contains more than one leaf");
    }

    let data = match leaf.entry().context("Failed to read RCDATA/27 leaf")? {
        Entry::DataEntry(d) => d,
        Entry::Directory(_) => bail!("RCDATA/27 leaf is a directory, expected data"),
    };

    let rva = data.image().OffsetToData;
    let size = data.image().Size;

    let file_off = match &pe {
        Wrap::T64(p) => {
            use pelite::pe64::Pe as _;
            p.rva_to_file_offset(rva).context("RVA→file-offset failed (PE64)")?
        }
        Wrap::T32(p) => {
            use pelite::pe32::Pe as _;
            p.rva_to_file_offset(rva).context("RVA→file-offset failed (PE32)")?
        }
    };

    Ok(file_off as u64 + size as u64)
}
