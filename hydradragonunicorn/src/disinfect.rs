// disinfect.rs — Generic, definition-driven disinfection of in-memory files.
//
// A disinfector only acts when a definition RECOGNISES the infection by
// signature (YAML, `disinfect_rules/default.yaml`, format in
// DISINFECT_FORMAT.md). The file is emulated with Unicorn in the unpacker's
// Windows environment; the definition then recovers the host (stored original
// entry point / bytes, or by following the virus back into the host and taking
// what it restored) and cuts the virus out. The repaired file is emulated again
// and must no longer be recognised. Nothing is ever written to disk here.
//
// Whether the caller should use the repaired file is a separate decision: a
// repaired program is not the original, so for anything but a system file
// deleting and reinstalling (or restoring a clean copy) is the safer advice.

mod engine;
mod pe_edit;
pub mod rules;

pub use rules::{DisinfectRules, VirusRule};

/// File name of the extra disinfection definitions shipped next to the HydraDragonSig
/// rules (`hydradragonsig_rules/`). It is not a HydraDragonSig rule file: rule loaders
/// that read every YAML in that folder skip it.
pub const DISINFECT_RULES_FILE: &str = "disinfect_rules.yaml";

use engine::{Plan, PlannedCleanup};
use pe_edit as pe;

/// Result of [`disinfect_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisinfectOutcome {
    /// No known (signature) infection was found.
    NotInfected,
    /// The infection was removed; `data` is the repaired file.
    Disinfected {
        malware_name: String,
        data: Vec<u8>,
        /// Bytes cut off (the virus body appended to the file).
        removed_bytes: usize,
    },
    /// The infection is known but cannot be removed safely (e.g. patient zero).
    NotRepairable { malware_name: String, reason: String },
}

/// Run the built-in definitions over `raw`.
pub fn disinfect_bytes(raw: &[u8]) -> DisinfectOutcome {
    disinfect_bytes_with(raw, DisinfectRules::builtin())
}

/// Name of the virus a definition recognises in `raw` (no repair attempted).
pub fn detect_bytes_with(raw: &[u8], rules: &DisinfectRules) -> Option<String> {
    engine::emulate(raw, &rules.rules).map(|d| rules.rules[d.rule].rule.name.clone())
}

/// Run the given definitions over `raw`: the first one that recognises it decides.
pub fn disinfect_bytes_with(raw: &[u8], rules: &DisinfectRules) -> DisinfectOutcome {
    let Some(found) = engine::emulate(raw, &rules.rules) else {
        return DisinfectOutcome::NotInfected;
    };
    let rule = &rules.rules[found.rule];
    let name = rule.rule.name.clone();
    let not_repairable = |reason: String| DisinfectOutcome::NotRepairable { malware_name: name.clone(), reason };
    let plan = match found.plan {
        Ok(p) => p,
        Err(e) => return not_repairable(e),
    };
    let data = match apply(raw, &plan, rule.rule.fix_checksum) {
        Ok(d) => d,
        Err(e) => return not_repairable(format!("repair failed: {e}")),
    };
    // The repaired file must not be recognised any more (by this definition).
    let single = DisinfectRules { rules: vec![rule.clone()] };
    if engine::emulate(&data, &single.rules).is_some() {
        return not_repairable("the virus is still recognised after the repair".into());
    }
    log::info!(
        "disinfect: {name} at 0x{:x}, entry point restored to 0x{:x}, {} block(s) of original code",
        found.virus_start,
        plan.oep,
        plan.restores.len()
    );
    DisinfectOutcome::Disinfected { malware_name: name, removed_bytes: raw.len().saturating_sub(data.len()), data }
}

fn rva(plan: &Plan, va: u64) -> Result<u32, String> {
    va.checked_sub(plan.image_base)
        .and_then(|r| u32::try_from(r).ok())
        .ok_or_else(|| format!("address 0x{va:x} is outside the image"))
}

/// Restore the host and cut the virus out of a copy of `raw`.
fn apply(raw: &[u8], plan: &Plan, fix_checksum: bool) -> Result<Vec<u8>, String> {
    let mut d = raw.to_vec();
    let l = pe::layout(&d)?;
    let had_checksum = pe::checksum(&d, &l) != 0;
    let secs = pe::sections(&d, &l);

    let mut restored = Vec::new();
    for (va, bytes) in &plan.restores {
        let r = rva(plan, *va)?;
        let off = pe::rva_to_offset(&secs, r, bytes.len())
            .ok_or_else(|| format!("original code at 0x{va:x} is outside the file data"))?;
        d[off..off + bytes.len()].copy_from_slice(bytes);
        restored.push((r, off, bytes.len()));
    }
    let oep = rva(plan, plan.oep)?;
    pe::set_entry_point(&mut d, &l, oep)?;

    for c in &plan.cleanup {
        let secs = pe::sections(&d, &pe::layout(&d)?);
        match *c {
            PlannedCleanup::TruncateVa(va) => {
                let off = pe::rva_to_offset(&secs, rva(plan, va)?, 0)
                    .ok_or_else(|| format!("cut address 0x{va:x} is outside the file data"))?;
                pe::truncate_at(&mut d, off)?;
            }
            PlannedCleanup::RemoveSectionOf(va) => {
                let s = pe::section_of_rva(&secs, rva(plan, va)?).ok_or("virus start is in no section")?;
                pe::remove_section(&mut d, s.index)?;
            }
            PlannedCleanup::ZeroRange(lo, hi) => {
                let r = rva(plan, lo)?;
                let s = pe::section_of_rva(&secs, r).ok_or("virus body is in no section")?;
                // Only the part stored in the file; the rest is zero-filled memory.
                let file_end = s.va.saturating_add(s.raw_size);
                let end = (rva(plan, hi)?).min(file_end);
                if end > r {
                    let off = pe::rva_to_offset(&secs, r, (end - r) as usize).ok_or("virus body is outside the file data")?;
                    d[off..off + (end - r) as usize].fill(0);
                }
            }
        }
    }

    // Sanity: the entry point and the restored code are still in the file, the
    // entry point lands in a section that survived the cleanup.
    let l = pe::layout(&d)?;
    let secs = pe::sections(&d, &l);
    if pe::rva_to_offset(&secs, oep, 1).is_none() {
        return Err(format!("restored entry point RVA 0x{oep:x} is not in the repaired file"));
    }
    for (r, off, len) in restored {
        if pe::rva_to_offset(&secs, r, len) != Some(off) {
            return Err(format!("restored code at RVA 0x{r:x} was removed by the cleanup"));
        }
    }
    if fix_checksum && had_checksum {
        crate::unpacker::imagedump::fix_checksum(&mut d).map_err(|e| e.to_string())?;
    }
    Ok(d)
}

#[cfg(test)]
mod tests;
