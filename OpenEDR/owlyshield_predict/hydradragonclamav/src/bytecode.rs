//! ClamAV bytecode (`.cbc`).
//!
//! **Stage 1 — `.cbc` header/trigger parsing.**
//!
//! ClamAV bytecode is a compiled program (ClamAV's own bytecode, derived from
//! LLVM bitcode) that runs inside a virtual machine to make complex detection
//! decisions. Each `.cbc` text file is:
//!   * line 1 — a `ClamBC…` header (format version, type table, functionality
//!     level), and
//!   * line 2 — a standard *logical-signature trigger* that decides when the
//!     bytecode runs, followed by the encoded program body.
//!
//! This module parses each program's header and trigger so they can be
//! enumerated and later executed. It does **not** execute bytecode yet — that
//! is a follow-on stage (a bytecode VM). Crucially, a trigger match alone is
//! *not* a detection: the trigger is a coarse prefilter and the program body
//! makes the real verdict, so triggers must never be wired as standalone
//! detections (that would false-positive).

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
    /// Load loose `*.cbc` files found directly in `dir`.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut set = BytecodeSet::default();
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

    /// Load bytecode from a pre-read map of filename → file contents.
    /// Only `*.cbc` files are processed; everything else is ignored.
    pub fn from_bytes_map(files: &std::collections::HashMap<String, Vec<u8>>) -> Self {
        let mut set = BytecodeSet::default();
        for (name, bytes) in files {
            if !name.ends_with(".cbc") {
                continue;
            }
            set.report.files_seen += 1;
            let text = String::from_utf8_lossy(bytes);
            match parse_cbc(&text) {
                Some(bc) => {
                    set.bytecodes.push(bc);
                    set.report.loaded += 1;
                }
                None => set.report.skipped += 1,
            }
        }
        set
    }
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
