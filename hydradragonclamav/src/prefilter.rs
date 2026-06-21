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
/// candidate on real data and trigger wasted rescans. 8 bytes is the balance:
/// still selective enough that a candidate almost always truly matches (so the
/// fast anchored matcher rarely does wasted work). NOTE: until verification is
/// offset-threaded, each candidate costs one full-buffer `memmem`, so candidate
/// count dominates scan time — and a shorter atom (e.g. 8) is far less selective
/// (≈5x more candidates ≈5x slower). 16 keeps the candidate set small; the trie
/// is larger but scans stay fast.
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
    /// Second automaton, over case-folded (lowercased) atoms harvested from
    /// `nocase` patterns (see `Pattern::required_atom_nocase`). `nocase`
    /// patterns never produce a `Token::Literal`, so they're invisible to the
    /// case-sensitive `ac` above; without this they'd all fall into
    /// `ext_always`/`log_always` and be evaluated on every single scan
    /// regardless of buffer content. Matched against a lowercased copy of the
    /// buffer in `candidates()`.
    ac_nocase: Option<DoubleArrayAhoCorasick<u32>>,
    num_atoms_nocase: usize,
    atom_starts_nocase: Vec<u32>,
    sig_refs_nocase: Vec<u64>,
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
            ac_nocase: None,
            num_atoms_nocase: 0,
            atom_starts_nocase: Vec::new(),
            sig_refs_nocase: Vec::new(),
            ext_always: Vec::new(),
            log_always: Vec::new(),
        }
    }

    /// Build the prefilter from a loaded database.
    pub fn build(db: &Database) -> Self {
        let mut entries: Vec<(Box<[u8]>, u64)> = Vec::new();
        let mut entries_nocase: Vec<(Box<[u8]>, u64)> = Vec::new();
        let mut ext_always: Vec<u32> = Vec::new();
        let mut log_always: Vec<u32> = Vec::new();

        // A pattern is usable for prefiltering via either its case-sensitive
        // atom or, for `nocase` patterns, its case-folded atom. Returns which
        // bucket the atom belongs in.
        enum Atom<'a> {
            Exact(&'a [u8]),
            Nocase(&'a [u8]),
        }
        fn pattern_atom(p: &crate::pattern::Pattern) -> Option<Atom<'_>> {
            if let Some(a) = p.required_atom() {
                if usable(a) {
                    return Some(Atom::Exact(a));
                }
            }
            if let Some(a) = p.required_atom_nocase() {
                if usable(a) {
                    return Some(Atom::Nocase(a));
                }
            }
            None
        }

        // --- Extended signatures: match if ANY pattern matches. ---
        for (si, sig) in db.extended.iter().enumerate() {
            let mut atoms: Vec<Atom> = Vec::with_capacity(sig.patterns.len());
            let mut atomless = sig.patterns.is_empty();
            for p in &sig.patterns {
                match pattern_atom(p) {
                    Some(a) => atoms.push(a),
                    None => {
                        atomless = true;
                        break;
                    }
                }
            }
            if atomless {
                ext_always.push(si as u32);
            } else {
                for a in atoms {
                    match a {
                        Atom::Exact(a) => entries.push((short_atom(a).into(), ext_ref(si))),
                        Atom::Nocase(a) => {
                            entries_nocase.push((short_atom(a).into(), ext_ref(si)))
                        }
                    }
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
            let mut best: Option<(usize, Vec<Atom>)> = None;
            for i in 0..n {
                let Subsignature::Body { patterns, .. } = &sig.subsignatures[i] else {
                    continue;
                };
                if patterns.is_empty() {
                    continue;
                }
                let mut atoms: Vec<Atom> = Vec::with_capacity(patterns.len());
                let mut ok = true;
                for p in patterns {
                    match pattern_atom(p) {
                        Some(a) => atoms.push(a),
                        None => {
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
                let max_len = atoms
                    .iter()
                    .map(|a| match a {
                        Atom::Exact(a) | Atom::Nocase(a) => a.len(),
                    })
                    .max()
                    .unwrap_or(0);
                if best.as_ref().map_or(true, |(bl, _)| max_len > *bl) {
                    best = Some((max_len, atoms));
                }
            }
            match best {
                Some((_, atoms)) => {
                    for a in atoms {
                        match a {
                            Atom::Exact(a) => entries.push((short_atom(a).into(), log_ref(si))),
                            Atom::Nocase(a) => {
                                entries_nocase.push((short_atom(a).into(), log_ref(si)))
                            }
                        }
                    }
                }
                None => log_always.push(si as u32),
            }
        }

        let (ac, num_atoms, atom_starts, sig_refs) = build_automaton(entries);
        let (ac_nocase, num_atoms_nocase, atom_starts_nocase, sig_refs_nocase) =
            build_automaton(entries_nocase);

        AtomPrefilter {
            ac,
            num_atoms,
            atom_starts,
            sig_refs,
            ac_nocase,
            num_atoms_nocase,
            atom_starts_nocase,
            sig_refs_nocase,
            ext_always,
            log_always,
        }
    }

    /// Candidate (extended, logical) signature sets for `data`.
    pub fn candidates(&self, data: &[u8]) -> (Candidates, Candidates) {
        if self.ac.is_none() && self.ac_nocase.is_none() {
            return (Candidates::All, Candidates::All);
        }

        let mut ext = self.ext_always.clone();
        let mut log = self.log_always.clone();

        if let Some(ac) = self.ac.as_ref() {
            collect_hits(
                ac,
                data,
                self.num_atoms,
                &self.atom_starts,
                &self.sig_refs,
                &mut ext,
                &mut log,
            );
        }

        if let Some(ac_nocase) = self.ac_nocase.as_ref() {
            // `nocase` atoms were case-folded to lowercase at build time, so
            // they must be matched against a lowercased copy of the buffer.
            let lowered: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
            collect_hits(
                ac_nocase,
                &lowered,
                self.num_atoms_nocase,
                &self.atom_starts_nocase,
                &self.sig_refs_nocase,
                &mut ext,
                &mut log,
            );
        }

        ext.sort_unstable();
        ext.dedup();
        log.sort_unstable();
        log.dedup();
        (Candidates::List(ext), Candidates::List(log))
    }
}

/// Run one Aho-Corasick pass over `haystack` and append matching signature
/// refs (deduped per atom id) into `ext`/`log`.
fn collect_hits(
    ac: &DoubleArrayAhoCorasick<u32>,
    haystack: &[u8],
    num_atoms: usize,
    atom_starts: &[u32],
    sig_refs: &[u64],
    ext: &mut Vec<u32>,
    log: &mut Vec<u32>,
) {
    let mut seen = vec![false; num_atoms];
    for m in ac.find_overlapping_iter(haystack) {
        let id = m.value() as usize;
        if seen[id] {
            continue;
        }
        seen[id] = true;
        let start = atom_starts[id] as usize;
        let end = atom_starts[id + 1] as usize;
        for &r in &sig_refs[start..end] {
            if r & LOG_FLAG != 0 {
                log.push((r & !LOG_FLAG) as u32);
            } else {
                ext.push(r as u32);
            }
        }
    }
}

/// Unique-atom + CSR mapping, shared by the case-sensitive and nocase
/// automaton builds.
#[allow(clippy::type_complexity)]
fn build_automaton(
    mut entries: Vec<(Box<[u8]>, u64)>,
) -> (
    Option<DoubleArrayAhoCorasick<u32>>,
    usize,
    Vec<u32>,
    Vec<u64>,
) {
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    // Collect unique atoms as *borrows* into `entries` (no per-atom `Box`
    // clone) plus the CSR mapping. daachorse copies the bytes into its trie at
    // build time, so `entries` can be dropped right after — this avoids holding
    // a second full copy of every atom during the build (a real peak-RAM spike
    // when there are hundreds of thousands of atoms).
    let mut atoms: Vec<&[u8]> = Vec::new();
    let mut atom_starts: Vec<u32> = Vec::new();
    let mut sig_refs: Vec<u64> = Vec::with_capacity(entries.len());
    let mut i = 0;
    while i < entries.len() {
        atom_starts.push(sig_refs.len() as u32);
        atoms.push(&entries[i].0);
        let cur = &entries[i].0;
        let mut j = i;
        while j < entries.len() && &entries[j].0 == cur {
            sig_refs.push(entries[j].1);
            j += 1;
        }
        i = j;
    }
    atom_starts.push(sig_refs.len() as u32); // sentinel

    let num_atoms = atoms.len();
    let ac = if atoms.is_empty() {
        None
    } else {
        DoubleArrayAhoCorasick::<u32>::new(&atoms).ok()
    };
    drop(atoms);
    drop(entries);
    (ac, num_atoms, atom_starts, sig_refs)
}
