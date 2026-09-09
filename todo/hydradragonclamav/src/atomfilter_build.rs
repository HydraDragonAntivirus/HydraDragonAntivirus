use daachorse::clamav_fast::ClamavFastScanner;

use crate::atomfilter::{AtomFilterDb, ExtSlot, PerTarget, SlotDef, SlotId, SubsigSlot};
use crate::database::Database;
use crate::logical::Subsignature;
use crate::pattern::Pattern;

/// Dynamic atom quality & entropy scoring function.
/// Evaluates the uniqueness/rarity of a byte sequence to adaptively choose the required minimum depth.
fn calculate_atom_entropy_score(bytes: &[u8]) -> u32 {
    let mut score = 0u32;
    for &b in bytes {
        let byte_score = match b {
            0x00 | 0xff | 0x20 | b'\n' | b'\r' | b'\t' => 1, // Low entropy / common padding
            b'a' | b'e' | b'i' | b'o' | b'u' | b'A' | b'E' | b'I' | b'O' | b'U' => 2, // Common vowels
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => 4, // Alphanumeric
            _ => 8, // High entropy byte (binary / rare opcode / symbol)
        };
        score += byte_score;
    }
    score
}

/// Dynamically determine if an atom is usable based on its length, byte entropy, and target file type.
#[inline]
fn is_atom_usable_dynamic(a: &[u8], target: u32) -> bool {
    let len = a.len();
    if len < 3 {
        return false;
    }

    let entropy_score = calculate_atom_entropy_score(a);

    // For Android APK/DEX targets (target == 0 or specific Android targets):
    // Require higher entropy or longer depth to prevent noise from ZIP/DEX structures.
    let min_required_score = if target == 0 {
        if len >= 6 {
            12
        } else if len >= 4 {
            16
        } else {
            20
        }
    } else {
        if len >= 5 {
            10
        } else if len >= 4 {
            14
        } else {
            18
        }
    };

    entropy_score >= min_required_score
}

const MAX_ATOM: usize = 16;

#[inline]
fn short_atom(a: &[u8]) -> Vec<u8> {
    a[..a.len().min(MAX_ATOM)].to_vec()
}

fn atom_threshold(_a: &Atom) -> u32 {
    1
}

enum Atom {
    Exact(Vec<u8>),
    Nocase(Vec<u8>),
}

fn pattern_atom(p: &Pattern, target: u32) -> Option<Atom> {
    if let Some(a) = p.required_atom() {
        if is_atom_usable_dynamic(&a, target) {
            return Some(Atom::Exact(short_atom(&a)));
        }
    }
    if let Some(a) = p.required_atom_nocase() {
        if is_atom_usable_dynamic(&a, target) {
            return Some(Atom::Nocase(short_atom(&a)));
        }
    }
    None
}

fn all_pattern_atoms(patterns: &[Pattern], target: u32) -> Option<Vec<Atom>> {
    if patterns.is_empty() {
        return None;
    }
    let mut atoms = Vec::with_capacity(patterns.len());
    for p in patterns {
        atoms.push(pattern_atom(p, target)?);
    }
    Some(atoms)
}

/// Collects unique (atom_bytes, slot_id) pairs for each atom type,
/// keyed by the slot's file_type_target.
struct AtomReg {
    exact: Vec<(Vec<u8>, SlotId, u32)>,
    nocase: Vec<(Vec<u8>, SlotId, u32)>,
}

impl AtomReg {
    fn register(&mut self, atom: &Atom, slot: SlotId, target: u32) {
        match atom {
            Atom::Exact(b) => self.exact.push((b.clone(), slot, target)),
            Atom::Nocase(b) => self.nocase.push((b.clone(), slot, target)),
        }
    }
}

fn build_automaton(
    entries: Vec<(Vec<u8>, SlotId)>,
    value_offset: u32,
) -> (
    Option<ClamavFastScanner<u32>>,
    Vec<Box<[SlotId]>>,
    Vec<usize>,
) {
    if entries.is_empty() {
        return (None, Vec::new(), Vec::new());
    }

    let mut pattern_to_slots: std::collections::HashMap<Vec<u8>, Vec<SlotId>> =
        std::collections::HashMap::new();
    for (bytes, slot) in entries {
        pattern_to_slots.entry(bytes).or_default().push(slot);
    }

    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(pattern_to_slots.len());
    let mut values: Vec<u32> = Vec::with_capacity(pattern_to_slots.len());
    let mut atom_to_slots: Vec<Box<[SlotId]>> = Vec::with_capacity(pattern_to_slots.len());
    let mut pattern_lens: Vec<usize> = Vec::with_capacity(pattern_to_slots.len());

    for (i, (bytes, slots)) in pattern_to_slots.into_iter().enumerate() {
        let value = value_offset + i as u32;
        patterns.push(bytes.clone());
        values.push(value);
        atom_to_slots.push(slots.into_boxed_slice());
        pattern_lens.push(bytes.len());
    }

    let pma = ClamavFastScanner::with_values(patterns.iter().cloned().zip(values.iter().copied()))
        .expect("ClamavFastScanner build should succeed");

    (Some(pma), atom_to_slots, pattern_lens)
}

/// Build per-target atom->slot mappings from the full registration table.
/// Returns Vec<(target, exact_entries, nocase_entries)> where each entry
/// contains only the atoms whose slots target `target` or 0 (any).
fn partition_by_target(
    all_exact: &[(Vec<u8>, SlotId, u32)],
    all_nocase: &[(Vec<u8>, SlotId, u32)],
    specific_targets: &[u32],
) -> Vec<(u32, Vec<(Vec<u8>, SlotId)>, Vec<(Vec<u8>, SlotId)>)> {
    let mut result = Vec::with_capacity(specific_targets.len() + 1);

    // Full automaton (target 0): ALL entries regardless of target.
    let full_exact: Vec<(Vec<u8>, SlotId)> =
        all_exact.iter().map(|(b, s, _)| (b.clone(), *s)).collect();
    let full_nocase: Vec<(Vec<u8>, SlotId)> =
        all_nocase.iter().map(|(b, s, _)| (b.clone(), *s)).collect();
    result.push((0, full_exact, full_nocase));

    // Per-target automata: only entries whose target matches *or* is 0 (any).
    for &target in specific_targets {
        let mut texact: Vec<(Vec<u8>, SlotId)> = Vec::new();
        let mut tnocase: Vec<(Vec<u8>, SlotId)> = Vec::new();
        for (b, s, t) in all_exact {
            if *t == target || *t == 0 {
                texact.push((b.clone(), *s));
            }
        }
        for (b, s, t) in all_nocase {
            if *t == target || *t == 0 {
                tnocase.push((b.clone(), *s));
            }
        }
        result.push((target, texact, tnocase));
    }

    result
}

pub struct AtomFilterBuilder;

impl AtomFilterBuilder {
    pub fn build(db: &Database) -> AtomFilterDb {
        let mut reg = AtomReg {
            exact: Vec::new(),
            nocase: Vec::new(),
        };
        let mut slots: Vec<SlotDef> = Vec::new();
        let mut ext_slot: Vec<ExtSlot> = Vec::with_capacity(db.extended.len());
        let mut log_subsig_slots: Vec<Box<[SubsigSlot]>> = Vec::with_capacity(db.logical.len());

        // ── Extended signatures ──────────────────────────────────────────
        for (si, sig) in db.extended.iter().enumerate() {
            let target = sig.target.unwrap_or(0);
            match all_pattern_atoms(&sig.patterns, target) {
                Some(atoms) => {
                    let slot_id = slots.len() as SlotId;
                    let threshold = atoms.iter().map(atom_threshold).max().unwrap_or(1);
                    slots.push(SlotDef {
                        target: crate::atomfilter::SlotTarget::Extended {
                            sig_index: si as u32,
                        },
                        threshold,
                        file_type_target: target,
                    });
                    for a in &atoms {
                        reg.register(a, slot_id, target);
                    }
                    ext_slot.push(ExtSlot::Atom(slot_id));
                }
                None => ext_slot.push(ExtSlot::AutoMatch),
            }
        }

        // ── Logical signatures ───────────────────────────────────────────
        for sig in db.logical.iter() {
            let target = sig.target.unwrap_or(0);
            let mut sub_slots: Vec<SubsigSlot> = Vec::with_capacity(sig.subsignatures.len());
            for subsig in sig.subsignatures.iter() {
                let Subsignature::Body { patterns, .. } = subsig else {
                    sub_slots.push(SubsigSlot::External);
                    continue;
                };
                match all_pattern_atoms(patterns, target) {
                    Some(atoms) => {
                        let slot_id = slots.len() as SlotId;
                        let sig_index = log_subsig_slots.len() as u32;
                        let subsig_index = sub_slots.len() as u32;
                        let threshold = atoms.iter().map(atom_threshold).max().unwrap_or(1);
                        slots.push(SlotDef {
                            target: crate::atomfilter::SlotTarget::LogicalSubsig {
                                sig_index,
                                subsig_index,
                            },
                            threshold,
                            file_type_target: target,
                        });
                        for a in &atoms {
                            reg.register(a, slot_id, target);
                        }
                        sub_slots.push(SubsigSlot::Atom(slot_id));
                    }
                    None => {
                        sub_slots.push(SubsigSlot::AutoMatch);
                    }
                }
            }
            log_subsig_slots.push(sub_slots.into_boxed_slice());
        }

        // ── Build the Shift-OR prefilter (all atoms) ─────────────────────
        let all_atoms: Vec<Vec<u8>> = reg
            .exact
            .iter()
            .chain(&reg.nocase)
            .map(|(bytes, _, _)| bytes.clone())
            .collect();
        let prefilter = daachorse::ClamavPrefilter::from_patterns(&all_atoms);

        // ── Identify which specific targets are present in the DB ────────
        let mut specific_targets: Vec<u32> = slots
            .iter()
            .filter_map(|s| {
                let t = s.file_type_target;
                (t != 0).then_some(t)
            })
            .collect();
        // Ensure per-target DFAs for all Android-relevant targets are built
        // even if no signature directly targets them. A buffer whose file type
        // is DEX (16) or APK (17) currently falls back to the "full" automaton
        // (which includes atoms for desktop-only targets 1, 2, 4, 9, 12 —
        // 34K+ useless file-type skips per large buffer). Adding them here
        // builds a smaller DFA containing only generic (target=0) atoms +
        // any target-specific atoms, eliminating the ft_sk waste entirely.
        specific_targets.extend_from_slice(&[16, 17, 18]);
        specific_targets.sort();
        specific_targets.dedup();

        // ── Partition atoms by target and build per-target automata ──────
        let partitions = partition_by_target(&reg.exact, &reg.nocase, &specific_targets);

        let mut per_target: Vec<PerTarget> = Vec::with_capacity(partitions.len());
        for (target, exact_entries, nocase_entries) in partitions {
            // Build exact automaton (values start at 0 for each target).
            let (exact, exact_atom_to_slots, exact_lens) = build_automaton(exact_entries, 0);

            // Build nocase automaton (values after exact entries).
            let nocase_offset = exact_atom_to_slots.len() as u32;
            let (nocase, nocase_atom_to_slots, nocase_lens) =
                build_automaton(nocase_entries, nocase_offset);

            // Merge value→slot arrays.
            let mut atom_to_slots = Vec::new();
            let mut pattern_lens = Vec::new();
            atom_to_slots.extend(exact_atom_to_slots);
            pattern_lens.extend(exact_lens);
            atom_to_slots.extend(nocase_atom_to_slots);
            pattern_lens.extend(nocase_lens);

            // Build reverse mapping (slot→values).
            let n_slots = slots.len();
            let mut slot_to_values: Vec<Vec<u32>> = vec![Vec::new(); n_slots];
            for (vi, slot_ids) in atom_to_slots.iter().enumerate() {
                for &sid in slot_ids.iter() {
                    slot_to_values[sid as usize].push(vi as u32);
                }
            }

            per_target.push(PerTarget {
                target,
                exact,
                nocase,
                atom_to_slots,
                pattern_lens,
                slot_to_values: slot_to_values
                    .into_iter()
                    .map(|v| v.into_boxed_slice())
                    .collect(),
            });
        }

        AtomFilterDb {
            per_target,
            slots,
            ext_slot,
            log_subsig_slots,
            prefilter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn load_str(name: &str, contents: &str) -> Database {
        let mut files = std::collections::HashMap::new();
        files.insert(name.to_string(), contents.as_bytes().to_vec());
        let (db, _report) = Database::from_bytes_map(&files);
        db
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn extended_signature_gets_one_atom_slot() {
        let hex = hex_of(b"HydraDragonTestAtom");
        let line = format!("Test.Ndb.Sig:0:*:{hex}\n");
        let db = load_str("test.ndb", &line);
        assert_eq!(db.extended.len(), 1);

        let afdb = AtomFilterBuilder::build(&db);
        assert_eq!(afdb.ext_slot.len(), 1);
        let ExtSlot::Atom(slot_id) = afdb.ext_slot[0] else {
            panic!("expected an atom slot, got {:?}", afdb.ext_slot[0]);
        };
        assert_eq!(
            afdb.slots[slot_id as usize].target,
            crate::atomfilter::SlotTarget::Extended { sig_index: 0 }
        );

        // The full (target=0) automaton must have been built.
        assert!(
            afdb.per_target
                .iter()
                .any(|pt| pt.target == 0 && pt.exact.is_some()),
            "expected exact automaton for target=0"
        );
    }

    #[test]
    fn logical_subsignature_gets_its_own_slot() {
        let hex_a = hex_of(b"AtomAlphaLiteral");
        let hex_b = hex_of(b"AtomBravoLiteral");
        let line = format!("Test.Ldb.Sig;Target:0;0&1;{hex_a};{hex_b}\n");
        let db = load_str("test.ldb", &line);
        assert_eq!(db.logical.len(), 1);
        assert_eq!(db.logical[0].subsignatures.len(), 2);

        let afdb = AtomFilterBuilder::build(&db);
        assert_eq!(afdb.log_subsig_slots.len(), 1);
        assert_eq!(afdb.log_subsig_slots[0].len(), 2);
        for (subsig_index, slot) in afdb.log_subsig_slots[0].iter().enumerate() {
            let SubsigSlot::Atom(slot_id) = *slot else {
                panic!("expected an atom slot for subsig {subsig_index}, got {slot:?}");
            };
            assert_eq!(
                afdb.slots[slot_id as usize].target,
                crate::atomfilter::SlotTarget::LogicalSubsig {
                    sig_index: 0,
                    subsig_index: subsig_index as u32
                }
            );
        }
    }

    #[test]
    fn target_filter_creates_separate_automata() {
        // NDB format: Name:TargetType:Offset:HexSig
        // Target 11 = SWF, target 6 = ELF.
        let swf_hex = hex_of(b"SwfOnlyMagic");
        let elf_hex = hex_of(b"ElfOnlyMagic");
        let ndb = format!("Test.Swf:11:*:{swf_hex}\nTest.Elf:6:*:{elf_hex}\n");
        let db = load_str("test.ndb", &ndb);
        let afdb = AtomFilterBuilder::build(&db);

        // Full (target=0) automaton has all patterns.
        let full = afdb.per_target.iter().find(|pt| pt.target == 0).unwrap();
        assert!(full.exact.is_some());

        // Target=11 automaton has SwfOnlyMagic.
        let swf = afdb.per_target.iter().find(|pt| pt.target == 11).unwrap();
        assert!(swf.exact.is_some());

        // Target=6 automaton has ElfOnlyMagic.
        let elf = afdb.per_target.iter().find(|pt| pt.target == 6).unwrap();
        assert!(elf.exact.is_some());

        // Full has both patterns; target-specific ones have fewer.
        assert!(full.atom_to_slots.len() > elf.atom_to_slots.len());
        assert!(full.atom_to_slots.len() > swf.atom_to_slots.len());
    }
}
