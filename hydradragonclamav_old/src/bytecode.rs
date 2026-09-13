//! ClamAV bytecode (`.cbc` / `bytecode.cvd` / `bytecode.cld`).
//!
//! **Stage 1 — container unpacking + `.cbc` header/trigger parsing.**
//!
//! ClamAV bytecode is a compiled program (ClamAV's own bytecode, derived from
//! LLVM bitcode) that runs inside a virtual machine to make complex detection
//! decisions. Each `.cbc` text file is:
//!   * line 1 — a `ClamBC…` header (format version, type table, functionality
//!     level), and
//!   * line 2 — a standard *logical-signature trigger* that decides when the
//!     bytecode runs, followed by the encoded program body.
//!
//! This module unpacks the bytecode container and parses each program's header
//! and trigger so they can be enumerated and later executed. It does **not**
//! execute bytecode yet — that is a follow-on stage (a bytecode VM). Crucially,
//! a trigger match alone is *not* a detection: the trigger is a coarse prefilter
//! and the program body makes the real verdict, so triggers must never be wired
//! as standalone detections (that would false-positive).

use std::fs;
use std::path::Path;

/// One loaded bytecode program. Stage 1 keeps the header, trigger and raw source;
/// the program body is decoded/executed in a later stage.
#[derive(Clone, Debug)]
pub struct Bytecode {
    /// Detection name from the trigger signature (e.g. `BC.Legacy.Exploit.…`).
    pub name: String,
    /// Raw trigger logical-signature line (line 2 of the `.cbc`), if present.
    pub trigger: Option<String>,
    /// Minimum engine functionality level the bytecode requires, if parseable.
    pub min_func_level: Option<u32>,
    /// Full `.cbc` source text, retained for the decoding/execution stage.
    pub source: String,
}

/// Counts from loading a bytecode container / directory.
#[derive(Clone, Debug, Default)]
pub struct BytecodeLoadReport {
    pub files_seen: usize,
    pub loaded: usize,
    pub skipped: usize,
}

/// The set of bytecodes loaded from a database directory.
#[derive(Clone, Debug, Default)]
pub struct BytecodeSet {
    pub bytecodes: Vec<Bytecode>,
    pub report: BytecodeLoadReport,
}

impl BytecodeSet {
    /// Load `bytecode.cvd` / `bytecode.cld` containers and any loose `*.cbc`
    /// files found directly in `dir`.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut set = BytecodeSet::default();

        for name in ["bytecode.cvd", "bytecode.cld"] {
            let p = dir.join(name);
            if p.exists() {
                if let Ok(data) = fs::read(&p) {
                    set.load_container(&data);
                }
            }
        }

        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("cbc") {
                    if let Ok(text) = fs::read_to_string(&p) {
                        set.report.files_seen += 1;
                        match parse_cbc(&text) {
                            Some(bc) => {
                                set.bytecodes.push(bc);
                                set.report.loaded += 1;
                            }
                            None => set.report.skipped += 1,
                        }
                    }
                }
            }
        }

        set
    }

    /// Unpack a `.cvd`/`.cld` container (512-byte ASCII header + gzipped tar) and
    /// parse every `ClamBC` entry inside. ClamAV uses old V7 tar (no `ustar`
    /// magic), so the tar is parsed directly rather than via the generic
    /// archive extractor.
    fn load_container(&mut self, data: &[u8]) {
        // `.cvd`/`.cld` start with a fixed 512-byte ASCII header; the gzipped tar
        // follows. A raw `.cbc` (no container) is handled by the loose-file path.
        let body = if data.starts_with(b"ClamAV-VDB:") && data.len() > 512 {
            &data[512..]
        } else {
            data
        };

        let Some(tar) = gunzip(body) else {
            return;
        };

        for entry in untar(&tar) {
            // `.cbc` files are ASCII text beginning with "ClamBC"; the container
            // also holds COPYING / bytecode.info, which we ignore.
            if !entry.starts_with(b"ClamBC") {
                continue;
            }
            self.report.files_seen += 1;
            match String::from_utf8(entry).ok().as_deref().and_then(parse_cbc) {
                Some(bc) => {
                    self.bytecodes.push(bc);
                    self.report.loaded += 1;
                }
                None => self.report.skipped += 1,
            }
        }
    }
}

/// Decompress a gzip stream fully into memory.
fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Minimal tar reader for the old V7 / ustar layout ClamAV emits: 512-byte
/// header blocks, file size as octal ASCII at offset 124..136, data padded to
/// 512-byte boundaries, terminated by zero blocks. Returns each member's bytes.
fn untar(data: &[u8]) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut pos = 0;
    while pos + 512 <= data.len() {
        let header = &data[pos..pos + 512];
        // A header whose name starts with NUL marks the end-of-archive blocks.
        if header[0] == 0 {
            break;
        }
        let size = parse_octal(&header[124..136]);
        pos += 512;
        if pos + size > data.len() {
            break;
        }
        files.push(data[pos..pos + size].to_vec());
        // Advance past the data, rounded up to the next 512-byte block.
        pos += size.div_ceil(512) * 512;
    }
    files
}

/// Parse a tar octal numeric field (space/NUL padded).
fn parse_octal(field: &[u8]) -> usize {
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .filter(|b| (b'0'..=b'7').contains(b))
        .collect();
    std::str::from_utf8(&digits)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 8).ok())
        .unwrap_or(0)
}

/// Parse a single `.cbc`'s header line and trigger line. Returns `None` if the
/// text isn't a ClamAV bytecode.
pub fn parse_cbc(text: &str) -> Option<Bytecode> {
    if !text.starts_with("ClamBC") {
        return None;
    }
    let mut lines = text.lines();
    let header = lines.next()?;
    // The header's trailing `:`-delimited field is the minimum functionality
    // level (a decimal); best-effort parse.
    let min_func_level = header
        .rsplit(':')
        .next()
        .and_then(|t| t.trim().parse::<u32>().ok());

    // Line 2 is the trigger logical signature: `name;TDB;expr;subsigs…`.
    let (name, trigger) = match lines.next() {
        Some(l) if l.contains(';') => (
            l.split(';').next().unwrap_or_default().to_string(),
            Some(l.to_string()),
        ),
        _ => (String::new(), None),
    };

    Some(Bytecode {
        name,
        trigger,
        min_func_level,
        source: text.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_trigger() {
        let cbc = "ClamBCabcd:4096\n\
                   BC.Legacy.Exploit.CVE_2010_1885-2;Engine:52-255,Target:3;0;6863703a2f2f\n\
                   Teddaaah...body...\n";
        let bc = parse_cbc(cbc).expect("should parse");
        assert_eq!(bc.name, "BC.Legacy.Exploit.CVE_2010_1885-2");
        assert_eq!(bc.min_func_level, Some(4096));
        assert!(bc.trigger.as_deref().unwrap().contains("Target:3"));
    }

    #[test]
    fn rejects_non_bytecode() {
        assert!(parse_cbc("not a bytecode").is_none());
    }
}
