//! `bytecode` condition: runs a ClamAV bytecode program (`.cbc`) over the scanned
//! bytes in hydradragonclamav's VM, for what declarative conditions cannot say
//! (variable-key decryption loops, walking data structures, checksums).
//!
//! Everything about the run is in the rule: the program, the entry function and
//! its arguments (`params`), the instruction budget (`max_ops`), what a match is
//! (`expect_return`, `virname_glob`; default: non-zero return or a virus name)
//! and new APIs. A program calls an API by the name its `E` line declares; when
//! the rule's `apis` has that name, the rule answers the call instead of the
//! ClamAV API table, from a constant, a parameter, a table, a fact about the
//! file or another condition (1 when it matches). `hds_param(i)` (= `params[i]`)
//! is always there.
//!
//! The program gets the file bytes as they are (no copy), the PE section table
//! and entry point for `pe_rawaddr` / `get_pe_section`. A program that fails to
//! load, errors or runs out of instructions makes the condition not match and
//! is logged; it never stops the scan.

use std::path::Path;

use super::types::RuleCondition;
use crate::models::ScanReport;

/// Instruction budget when the rule sets none.
#[cfg_attr(not(feature = "bytecode"), allow(dead_code))]
pub const DEFAULT_MAX_OPS: u64 = 100_000;
/// Highest `max_ops` a rule may ask for (about a second of interpreter time).
pub const MAX_MAX_OPS: u64 = 12_000_000;

/// Fact names an API may return (`fact:`).
pub const FACTS: &[&str] = &[
    "file.size",
    "file.entropy_x1000",
    "file.is_pe",
    "pe.sections",
    "pe.imports",
    "pe.exports",
    "pe.dlls",
    "pe.suspicious_imports",
    "pe.entry",
    "pe.image_base",
    "pe.timestamp",
    "pe.is_64",
    "pe.packed",
    "strings.count",
];

/// Resolves a rule's relative `program` against the rule file's folder.
pub fn rebase_program(cond: &mut RuleCondition, dir: &Path) {
    if let RuleCondition::Bytecode { program, apis, .. } = cond {
        let p = Path::new(program.as_str());
        if p.is_relative() && !program.trim().is_empty() {
            *program = dir.join(p).to_string_lossy().into_owned();
        }
        for api in apis.values_mut() {
            if let Some(c) = api.condition.as_mut() {
                rebase_program(c, dir);
            }
        }
    }
}

#[cfg(feature = "bytecode")]
mod vm {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use once_cell::sync::Lazy;

    use super::super::types::BytecodeApi;
    use hydradragonclamav::bytecode_vm::{self, Bc, HostApis, PeSection};

    /// Decoded and prepared programs by path; `None` when it could not be loaded.
    static PROGRAMS: Lazy<Mutex<HashMap<PathBuf, Option<Arc<Bc>>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    fn load(path: &Path) -> Result<Arc<Bc>, String> {
        if let Some(p) = PROGRAMS.lock().unwrap().get(path) {
            return p.clone().ok_or_else(|| "could not be loaded (see the earlier warning)".into());
        }
        let loaded = (|| -> Result<Bc, String> {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let mut bc = bytecode_vm::decode_bytecode(&text)
                .map_err(|e| format!("{e:?}"))?
                .ok_or("skipped: unsupported format level, type ids or engine level")?;
            bc.prepare_interpreter().map_err(|e| format!("{e:?}"))?;
            Ok(bc)
        })();
        let entry = loaded.as_ref().ok().map(|bc| Arc::new(bc.clone()));
        if let Err(e) = &loaded {
            log::warn!("bytecode program {}: {e}", path.display());
        }
        PROGRAMS.lock().unwrap().insert(path.to_path_buf(), entry.clone());
        entry.ok_or_else(|| loaded.err().unwrap_or_default())
    }

    struct RuleHost<'a> {
        apis: &'a std::collections::BTreeMap<String, BytecodeApi>,
        params: &'a [u64],
        report: &'a ScanReport,
        bytes: &'a [u8],
        nested: &'a dyn Fn(&RuleCondition) -> bool,
    }

    impl HostApis for RuleHost<'_> {
        fn call(&self, name: &str, args: &[u64]) -> Option<u64> {
            let arg0 = args.first().copied().unwrap_or(0) as usize;
            let Some(api) = self.apis.get(name) else {
                return (name == "hds_param").then(|| self.params.get(arg0).copied().unwrap_or(0));
            };
            Some(if let Some(v) = api.value {
                v as u64
            } else if let Some(i) = api.param {
                self.params.get(i).copied().unwrap_or(0)
            } else if api.param_arg {
                self.params.get(arg0).copied().unwrap_or(0)
            } else if !api.table.is_empty() {
                api.table.get(arg0).copied().unwrap_or(0) as u64
            } else if let Some(f) = api.fact.as_deref() {
                fact(f, self.report, self.bytes)
            } else if let Some(c) = api.condition.as_deref() {
                u64::from((self.nested)(c))
            } else {
                0
            })
        }
    }

    /// Runs the condition; the evidence when it matches.
    pub fn evaluate(cond: &RuleCondition, report: &ScanReport, bytes: &[u8], nested: &dyn Fn(&RuleCondition) -> bool) -> Option<String> {
        let RuleCondition::Bytecode { program, entry_func, max_ops, params, expect_return, virname_glob, apis } = cond else {
            return None;
        };
        let bc = match load(Path::new(program)) {
            Ok(bc) => bc,
            Err(_) => return None,
        };
        let (sections, ep, hdr_size) = pe_layout(report, bytes);
        let host = RuleHost { apis, params, report, bytes, nested };
        let budget = max_ops.unwrap_or(DEFAULT_MAX_OPS).clamp(1, MAX_MAX_OPS);
        let run = bytecode_vm::execute_bytecode_standalone(
            &bc,
            bytes,
            sections,
            ep,
            hdr_size,
            entry_func.unwrap_or(0),
            params,
            budget,
            Some(&host),
        );
        let (ret, virname) = match run {
            Ok(r) => r,
            Err(bytecode_vm::VmError::Timeout) => {
                log::warn!("bytecode {program}: stopped after {budget} instructions on {}", report.path.display());
                return None;
            }
            Err(e) => {
                log::warn!("bytecode {program}: {e:?} on {}", report.path.display());
                return None;
            }
        };
        let name_ok = match virname_glob.as_deref() {
            Some(g) => virname.as_deref().is_some_and(|v| super::super::glob::glob_match(g, v)),
            None => true,
        };
        let ret_ok = match expect_return {
            Some(want) => ret == *want,
            None => ret != 0 || virname.is_some(),
        };
        (name_ok && ret_ok).then(|| {
            let shown = Path::new(program).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| program.clone());
            match virname {
                Some(v) => format!("bytecode {shown} returned {ret}, virus name `{v}`"),
                None => format!("bytecode {shown} returned {ret}"),
            }
        })
    }

    /// Section table, entry point (file offset) and header size, as ClamAV's
    /// `cli_exe_info` gives them to bytecode.
    fn pe_layout(report: &ScanReport, bytes: &[u8]) -> (Vec<PeSection>, u32, u32) {
        let Some(pe) = report.pe.as_ref() else { return (Vec::new(), 0, 0) };
        let sections: Vec<PeSection> = pe
            .sections
            .iter()
            .map(|s| PeSection {
                rva: s.virtual_address as u32,
                vsz: s.virtual_size as u32,
                raw: s.raw_offset as u32,
                rsz: s.raw_size as u32,
                chr: s.characteristics,
                urva: s.virtual_address as u32,
                uvsz: s.virtual_size as u32,
                uraw: s.raw_offset as u32,
                ursz: s.raw_size as u32,
            })
            .collect();
        let ep = super::super::pe_extra::rva_file_offset(pe, bytes, pe.entry).unwrap_or(0) as u32;
        let hdr_size = pe.sections.iter().map(|s| s.raw_offset).filter(|&o| o > 0).min().unwrap_or(0) as u32;
        (sections, ep, hdr_size)
    }
}

#[cfg(feature = "bytecode")]
pub use vm::evaluate;

/// Built without the `bytecode` feature: the condition never matches.
#[cfg(not(feature = "bytecode"))]
pub fn evaluate(_cond: &RuleCondition, _report: &ScanReport, _bytes: &[u8], _nested: &dyn Fn(&RuleCondition) -> bool) -> Option<String> {
    None
}

/// The value of a `fact:` (0 for one the file does not have).
#[cfg_attr(not(feature = "bytecode"), allow(dead_code))]
pub fn fact(name: &str, report: &ScanReport, bytes: &[u8]) -> u64 {
    let pe = report.pe.as_ref();
    match name {
        "file.size" => bytes.len() as u64,
        "file.entropy_x1000" => {
            let e = if report.entropy > 0.0 { report.entropy } else { crate::utils::entropy::byte_entropy(bytes) };
            (e * 1000.0).round() as u64
        }
        "file.is_pe" => u64::from(pe.is_some()),
        "pe.sections" => pe.map_or(0, |p| p.sections.len() as u64),
        "pe.imports" => pe.map_or(0, |p| p.imports.len() as u64),
        "pe.exports" => pe.map_or(0, |p| p.exports.len() as u64),
        "pe.dlls" => pe.map_or(0, |p| p.dlls.len() as u64),
        "pe.suspicious_imports" => pe.map_or(0, |p| p.suspicious_imports.len() as u64),
        "pe.entry" => pe.map_or(0, |p| p.entry),
        "pe.image_base" => pe.map_or(0, |p| p.image_base),
        "pe.timestamp" => pe.map_or(0, |p| p.time_date_stamp as u64),
        "pe.is_64" => pe.map_or(0, |p| u64::from(p.is_64)),
        "pe.packed" => pe.map_or(0, |p| u64::from(p.likely_packed)),
        "strings.count" => report.strings.len() as u64,
        _ => 0,
    }
}
