//! Atom prefilter — one shared Aho-Corasick pass (daachorse, the matcher yara-x
//! uses) that picks *which* signatures to fully evaluate for a buffer, instead of
//! testing all ~500k linearly.
//!
//! ClamAV-style: we index a **short 2–3 byte static atom** from every signature
//! (a depth-limited trie), not the full literal. Short atoms keep the automaton
//! shallow and cheap to build, and every signature with any ≥2-byte literal gets
//! covered — so there's no large "always-check" linear set. The full pattern is
//! still verified afterward (`find_all` re-checks the longer literal via memchr),
//! so a coarse 2–3 byte atom never causes a false detection.
//!
//! Correctness: a signature is skipped only when it provably cannot match (none
//! of its required atoms occur and it can't fire at zero matches).

use daachorse::DoubleArrayAhoCorasick;

use crate::database::Database;
use crate::logical::Subsignature;

/// Shortest literal usable as an atom (ClamAV's AC mindepth is 2).
const MIN_DEPTH: usize = 2;
/// Longest atom we index per signature. ClamAV uses a tiny 2–3 byte atom because
/// its Aho-Corasick pass yields the exact *offset*, so the follow-up verify is
/// O(1). Our verify re-confirms the full literal with `memmem` (no offset is
/// threaded through), so a 2–3 byte atom would mark nearly every signature a
/// candidate on real data and trigger ~65k wasted rescans. A longer atom (up to
/// 16 bytes, one per signature) is selective enough that a candidate almost
/// always truly matches — while still indexing every signature, and ~70–150k
/// atoms of ≤16 bytes build a cheap, shallow trie (no RAM blowup).
const MAX_ATOM: usize = 16;

/// A signature reference packed into a u64: top bit = logical, low bits = index.
const LOG_FLAG: u64 = 1 << 63;

#[inline]
fn ext_ref(i: usize) -> u64 {
    i as u64
}
#[inline]
fn log_ref(i: usize) -> u64 {
    i as u64 | LOG_FLAG
}
/// The atom indexed for a literal: its first `MAX_ATOM` bytes.
#[inline]
fn short_atom(a: &[u8]) -> &[u8] {
    &a[..a.len().min(MAX_ATOM)]
}
#[inline]
fn usable(a: &[u8]) -> bool {
    a.len() >= MIN_DEPTH
}

/// Which signatures to evaluate for a buffer.
pub enum Candidates {
    All,
    List(Vec<u32>),
}

pub struct AtomPrefilter {
    ac: Option<DoubleArrayAhoCorasick<u32>>,
    num_atoms: usize,
    /// CSR: `sig_refs[atom_starts[id]..atom_starts[id+1]]` = candidate sigs for atom id.
    atom_starts: Vec<u32>,
    sig_refs: Vec<u64>,
    ext_always: Vec<u32>,
    log_always: Vec<u32>,
}

impl std::fmt::Debug for AtomPrefilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomPrefilter")
            .field("atoms", &self.num_atoms)
            .field("ext_always", &self.ext_always.len())
            .field("log_always", &self.log_always.len())
            .finish()
    }
}

impl AtomPrefilter {
    pub fn disabled() -> Self {
        AtomPrefilter {
            ac: None,
            num_atoms: 0,
            atom_starts: Vec::new(),
            sig_refs: Vec::new(),
            ext_always: Vec::new(),
            log_always: Vec::new(),
        }
    }

    /// Build the prefilter from a loaded database.
    pub fn build(db: &Database) -> Self {
        let mut entries: Vec<(Box<[u8]>, u64)> = Vec::new();
        let mut ext_always: Vec<u32> = Vec::new();
        let mut log_always: Vec<u32> = Vec::new();

        // --- Extended signatures: match if ANY pattern matches. ---
        for (si, sig) in db.extended.iter().enumerate() {
            let mut atoms: Vec<&[u8]> = Vec::with_capacity(sig.patterns.len());
            let mut atomless = sig.patterns.is_empty();
            for p in &sig.patterns {
                match p.required_atom() {
                    Some(a) if usable(a) => atoms.push(short_atom(a)),
                    _ => {
                        atomless = true;
                        break;
                    }
                }
            }
            if atomless {
                ext_always.push(si as u32);
            } else {
                for a in atoms {
                    entries.push((a.into(), ext_ref(si)));
                }
            }
        }

        // --- Logical signatures: index ONE *required* subsignature's atoms. ---
        let probe_present = 1usize << 30;
        for (si, sig) in db.logical.iter().enumerate() {
            let n = sig.subsignatures.len();
            if sig.expression.eval(&vec![0usize; n]).matched {
                log_always.push(si as u32);
                continue;
            }
            let mut best: Option<(usize, Vec<&[u8]>)> = None;
            for i in 0..n {
                let Subsignature::Body { patterns, .. } = &sig.subsignatures[i] else {
                    continue;
                };
                if patterns.is_empty() {
                    continue;
                }
                let mut atoms: Vec<&[u8]> = Vec::with_capacity(patterns.len());
                let mut ok = true;
                for p in patterns {
                    match p.required_atom() {
                        Some(a) if usable(a) => atoms.push(short_atom(a)),
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                let mut probe = vec![probe_present; n];
                probe[i] = 0;
                if sig.expression.eval(&probe).matched {
                    continue; // not required
                }
                let max_len = atoms.iter().map(|a| a.len()).max().unwrap_or(0);
                if best.as_ref().map_or(true, |(bl, _)| max_len > *bl) {
                    best = Some((max_len, atoms));
                }
            }
            match best {
                Some((_, atoms)) => {
                    for a in atoms {
                        entries.push((a.into(), log_ref(si)));
                    }
                }
                None => log_always.push(si as u32),
            }
        }

        // --- Unique short atoms + CSR mapping. ---
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut atoms: Vec<Box<[u8]>> = Vec::new();
        let mut atom_starts: Vec<u32> = Vec::new();
        let mut sig_refs: Vec<u64> = Vec::with_capacity(entries.len());
        let mut i = 0;
        while i < entries.len() {
            atom_starts.push(sig_refs.len() as u32);
            atoms.push(entries[i].0.clone());
            let cur = &entries[i].0;
            let mut j = i;
            while j < entries.len() && &entries[j].0 == cur {
                sig_refs.push(entries[j].1);
                j += 1;
            }
            i = j;
        }
        atom_starts.push(sig_refs.len() as u32); // sentinel
        drop(entries);

        let num_atoms = atoms.len();
        let ac = if atoms.is_empty() {
            None
        } else {
            // Short (≤3 byte) atoms → a shallow double-array trie, cheap to build.
            DoubleArrayAhoCorasick::<u32>::new(&atoms).ok()
        };

        AtomPrefilter {
            ac,
            num_atoms,
            atom_starts,
            sig_refs,
            ext_always,
            log_always,
        }
    }

    /// Candidate (extended, logical) signature sets for `data`.
    pub fn candidates(&self, data: &[u8]) -> (Candidates, Candidates) {
        let Some(ac) = self.ac.as_ref() else {
            return (Candidates::All, Candidates::All);
        };

        let mut ext = self.ext_always.clone();
        let mut log = self.log_always.clone();
        let mut seen = vec![false; self.num_atoms];

        for m in ac.find_overlapping_iter(data) {
            let id = m.value() as usize;
            if seen[id] {
                continue;
            }
            seen[id] = true;
            let start = self.atom_starts[id] as usize;
            let end = self.atom_starts[id + 1] as usize;
            for &r in &self.sig_refs[start..end] {
                if r & LOG_FLAG != 0 {
                    log.push((r & !LOG_FLAG) as u32);
                } else {
                    ext.push(r as u32);
                }
            }
        }

        ext.sort_unstable();
        ext.dedup();
        log.sort_unstable();
        log.dedup();
        (Candidates::List(ext), Candidates::List(log))
    }
}
