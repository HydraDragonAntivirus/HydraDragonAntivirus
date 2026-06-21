//! Atom prefilter — the single shared matcher that decides *which* signatures to
//! fully evaluate for a given buffer, instead of testing all ~500k linearly.
//!
//! Every body pattern has a longest required literal ("atom"): a case-sensitive
//! byte string that MUST appear for the pattern to match. We build one
//! Aho-Corasick automaton over every signature's atoms; scanning a buffer runs
//! that automaton once (O(buffer)) and yields the set of atoms present, from
//! which we derive the small set of candidate signatures. Signatures that can
//! match without any atom present (no usable atom, PCRE/byte-compare subsigs, or
//! a logical expression satisfiable at zero matches) are always evaluated.
//!
//! This is conservative: a signature is skipped only when it provably cannot
//! match (none of its atoms occur and it can't fire at zero matches), so results
//! are identical to the exhaustive scan.

use std::collections::HashMap;

use daachorse::DoubleArrayAhoCorasick;

use crate::database::Database;
use crate::logical::Subsignature;

/// Minimum atom length worth indexing. 1-byte atoms match almost everywhere and
/// would make the prefilter useless, so such patterns are treated as atomless.
const MIN_ATOM_LEN: usize = 4;

/// Which signatures to evaluate for a buffer.
pub enum Candidates {
    /// Evaluate every signature (prefilter disabled / unavailable).
    All,
    /// Evaluate only these signature indices (sorted, deduplicated).
    List(Vec<u32>),
}

pub struct AtomPrefilter {
    enabled: bool,
    ac: Option<DoubleArrayAhoCorasick<u32>>,
    num_atoms: usize,
    /// atom id -> extended signature indices whose match requires that atom.
    ext_by_atom: Vec<Vec<u32>>,
    /// atom id -> logical signature indices.
    log_by_atom: Vec<Vec<u32>>,
    /// Signatures that must always be evaluated (can match with no atom present).
    ext_always: Vec<u32>,
    log_always: Vec<u32>,
}

impl std::fmt::Debug for AtomPrefilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomPrefilter")
            .field("enabled", &self.enabled)
            .field("num_atoms", &self.num_atoms)
            .field("ext_always", &self.ext_always.len())
            .field("log_always", &self.log_always.len())
            .finish()
    }
}

impl AtomPrefilter {
    /// A no-op prefilter that always evaluates every signature.
    pub fn disabled() -> Self {
        AtomPrefilter {
            enabled: false,
            ac: None,
            num_atoms: 0,
            ext_by_atom: Vec::new(),
            log_by_atom: Vec::new(),
            ext_always: Vec::new(),
            log_always: Vec::new(),
        }
    }

    /// Build the prefilter from a loaded database.
    pub fn build(db: &Database) -> Self {
        let mut atom_ids: HashMap<Vec<u8>, u32> = HashMap::new();
        let mut atoms: Vec<Vec<u8>> = Vec::new();
        let mut ext_by_atom: Vec<Vec<u32>> = Vec::new();
        let mut log_by_atom: Vec<Vec<u32>> = Vec::new();
        let mut ext_always: Vec<u32> = Vec::new();
        let mut log_always: Vec<u32> = Vec::new();

        let mut intern = |atom: &[u8],
                          atoms: &mut Vec<Vec<u8>>,
                          ext_by_atom: &mut Vec<Vec<u32>>,
                          log_by_atom: &mut Vec<Vec<u32>>|
         -> u32 {
            if let Some(&id) = atom_ids.get(atom) {
                return id;
            }
            let id = atoms.len() as u32;
            atoms.push(atom.to_vec());
            ext_by_atom.push(Vec::new());
            log_by_atom.push(Vec::new());
            atom_ids.insert(atom.to_vec(), id);
            id
        };

        // --- Extended (body) signatures: match if ANY pattern matches. ---
        for (si, sig) in db.extended.iter().enumerate() {
            let mut sig_atoms: Vec<u32> = Vec::new();
            let mut always = sig.patterns.is_empty();
            for p in &sig.patterns {
                match p.required_atom() {
                    Some(a) if a.len() >= MIN_ATOM_LEN => {
                        sig_atoms.push(intern(a, &mut atoms, &mut ext_by_atom, &mut log_by_atom));
                    }
                    // A pattern with no usable atom can match anywhere → the whole
                    // signature must always be checked.
                    _ => always = true,
                }
            }
            if always {
                ext_always.push(si as u32);
            } else {
                sig_atoms.sort_unstable();
                sig_atoms.dedup();
                for id in sig_atoms {
                    ext_by_atom[id as usize].push(si as u32);
                }
            }
        }

        // --- Logical signatures. ---
        for (si, sig) in db.logical.iter().enumerate() {
            // A signature whose expression is satisfied with all-zero counts can
            // fire without any subsignature matching (e.g. a `0<5` count test), so
            // it can never be prefiltered away.
            let zero = vec![0usize; sig.subsignatures.len()];
            let mut always = sig.expression.eval(&zero).matched;

            let mut sig_atoms: Vec<u32> = Vec::new();
            for sub in &sig.subsignatures {
                match sub {
                    Subsignature::Body { patterns, .. } => {
                        let mut sub_always = patterns.is_empty();
                        for p in patterns {
                            match p.required_atom() {
                                Some(a) if a.len() >= MIN_ATOM_LEN => sig_atoms.push(intern(
                                    a,
                                    &mut atoms,
                                    &mut ext_by_atom,
                                    &mut log_by_atom,
                                )),
                                _ => sub_always = true,
                            }
                        }
                        // A body subsig that can match with no atom makes the whole
                        // signature unprefilterable.
                        if sub_always {
                            always = true;
                        }
                    }
                    // PCRE / byte-compare / unsupported subsigs aren't atom-indexed;
                    // be conservative and always evaluate such signatures.
                    _ => always = true,
                }
            }

            if always || sig_atoms.is_empty() {
                log_always.push(si as u32);
            } else {
                sig_atoms.sort_unstable();
                sig_atoms.dedup();
                for id in sig_atoms {
                    log_by_atom[id as usize].push(si as u32);
                }
            }
        }

        let num_atoms = atoms.len();
        // Drop the interning map before building the automaton to keep peak
        // memory down (the double-array build is the other large allocation).
        drop(atom_ids);
        let ac = if atoms.is_empty() {
            None
        } else {
            // daachorse's double-array trie holds ~1M atoms in a fraction of the
            // memory a classic NFA/DFA would. Values are the atom ids (0..n).
            DoubleArrayAhoCorasick::<u32>::new(&atoms).ok()
        };
        let enabled = ac.is_some();

        AtomPrefilter {
            enabled,
            ac,
            num_atoms,
            ext_by_atom,
            log_by_atom,
            ext_always,
            log_always,
        }
    }

    /// Candidate (extended, logical) signature sets for `data`.
    pub fn candidates(&self, data: &[u8]) -> (Candidates, Candidates) {
        let Some(ac) = self.ac.as_ref() else {
            return (Candidates::All, Candidates::All);
        };
        if !self.enabled {
            return (Candidates::All, Candidates::All);
        }

        let mut seen = vec![false; self.num_atoms];
        let mut ext = self.ext_always.clone();
        let mut log = self.log_always.clone();

        for m in ac.find_overlapping_iter(data) {
            let id = m.value() as usize;
            if !seen[id] {
                seen[id] = true;
                ext.extend_from_slice(&self.ext_by_atom[id]);
                log.extend_from_slice(&self.log_by_atom[id]);
            }
        }

        ext.sort_unstable();
        ext.dedup();
        log.sort_unstable();
        log.dedup();
        (Candidates::List(ext), Candidates::List(log))
    }
}
