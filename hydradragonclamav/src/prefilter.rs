//! Atom prefilter — one shared Aho-Corasick pass (daachorse, the matcher yara-x
//! uses) that picks *which* signatures to fully evaluate for a buffer, instead of
//! testing all ~500k linearly.
//!
//! ClamAV-style: we index a **short static atom** (the leading bytes of a
//! signature's required literal) from every signature, not the full literal. One
//! pass over the buffer reports, for every candidate signature, the exact byte
//! offsets where its atom occurs. Those offsets are **threaded into
//! verification** (`Pattern::find_all_at`): the full pattern is checked only at
//! `offset - prefix`, never by rescanning the whole buffer. This mirrors ClamAV's
//! `bp = i + 1 - depth` anchored match (matcher-ac.c) and is what keeps a scan of
//! a multi-megabyte file fast — without it, every candidate pays a full-buffer
//! `memmem`.
//!
//! Correctness: a signature is skipped only when it provably cannot match (none
//! of its required atoms occur and it can't fire at zero matches). Offset
//! threading never changes the match set — the atom is a *prefix* of the required
//! literal, so every literal occurrence is among the reported offsets, and the
//! full literal + pattern are re-verified at each (see `Pattern::find_all_at`).

use daachorse::DoubleArrayAhoCorasick;

use crate::database::{Database, OffsetAnchor, OffsetSpec};
use crate::logical::Subsignature;

/// Shortest literal usable as an atom (ClamAV's AC mindepth is 2).
const MIN_DEPTH: usize = 2;
/// Longest atom we index per signature. A longer atom is more selective (fewer
/// candidates), at the cost of a larger trie. 16 keeps the candidate set small
/// while the offset threading below makes the per-candidate verify O(hits).
const MAX_ATOM: usize = 16;

/// Cap on recorded occurrences of a *single atom* per scan. A short atom can
/// occur tens of thousands of times in a large binary; past this cap we stop
/// recording offsets and emit an overflow sentinel so the affected signatures
/// fall back to a full scan (bounds peak memory; correctness preserved).
const CAP_PER_ATOM: u32 = 256;
/// Cap on threaded offsets accumulated for a *single signature* (across all its
/// atoms). Beyond this, the signature falls back to a full scan.
const MAX_OFFSETS_PER_SIG: usize = 256;
/// Sentinel offset meaning "this atom overflowed — full-scan its signatures".
/// Safe because scanned buffers are < 2 GiB, so a real offset never reaches it.
const OFFSET_OVERFLOW: u32 = u32::MAX;

/// An atom's owner reference packed into a u64. Bit 63 = logical. For an extended
/// signature the low 40 bits are its index. For a logical signature the low 40
/// bits are the lsig index and bits 40..62 are the *subsignature* index — so the
/// one AC pass tells us exactly which `(lsig, subsig)` an atom belongs to and we
/// can verify and count that subsig directly (ClamAV's per-subsig AC counting),
/// instead of re-scanning the whole buffer for every candidate.
// sig: bits 0..31, subsig: bits 32..39, partno: bits 40..47, logical flag: bit 63.
// `partno` is the gap-part index for a gappy subsig (0 for non-gappy), so the one
// AC pass records, per `(lsig, subsig, part)`, exactly where each PART occurred —
// the scanner then verifies each part at its own offsets and stitches them by gap
// distance (ClamAV's `offmatrix`), instead of lumping all parts into one offset
// list that overflows the cap for multi-part patterns.
const LOG_FLAG: u64 = 1 << 63;
const SUBSIG_SHIFT: u64 = 32;
const PART_SHIFT: u64 = 40;

#[inline]
fn ext_ref(i: usize) -> u64 {
    i as u64
}
#[inline]
fn log_ref(sig: usize, subsig: usize, partno: usize) -> u64 {
    (sig as u64) | ((subsig as u64) << SUBSIG_SHIFT) | ((partno as u64) << PART_SHIFT) | LOG_FLAG
}
/// Unpack a logical ref into `(sig, subsig, partno)`.
#[inline]
fn log_unpack(r: u64) -> (u32, u32, u32) {
    let r = r & !LOG_FLAG;
    (
        (r & 0xFFFF_FFFF) as u32,
        ((r >> SUBSIG_SHIFT) & 0xFF) as u32,
        ((r >> PART_SHIFT) & 0xFF) as u32,
    )
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

/// Logical candidates with **per-subsignature** atom offsets — the core of
/// ClamAV-style matching. One AC pass records, for each candidate lsig, the
/// offsets where *each* of its subsignatures' atoms occurred, so a subsig is
/// verified only at those offsets (`find_all_at`) instead of re-scanning the whole
/// buffer. A candidate appears here only when ≥1 of its subsig atoms hit.
///
/// CSR layout for candidate `k`: its hit subsigs are `entry_subsig[e]` for
/// `e in entry_starts[k]..entry_starts[k+1]`, and that entry's offsets are
/// `offsets[off_starts[e]..off_starts[e+1]]`. An empty offset span for an entry
/// means that subsig's atom overflowed the cap → verify it by full scan.
pub struct LogCandidateSet {
    sigs: Vec<u32>,
    entry_starts: Vec<u32>,
    entry_subsig: Vec<u32>,
    off_starts: Vec<u32>,
    offsets: Vec<u32>,
}

/// Which logical signatures to evaluate. `All` (prefilter disabled / no atoms)
/// means evaluate every logical signature by full scan — the ground truth.
pub enum LogCandidates {
    All,
    List(LogCandidateSet),
}

/// The hit subsignatures + offsets for one logical candidate.
pub struct SubHits<'a> {
    subsigs: &'a [u32],
    off_starts: &'a [u32],
    offsets: &'a [u32],
    base: usize,
}

impl SubHits<'static> {
    /// A candidate with no recorded hits — every indexable subsig is treated as
    /// "atom absent" (count 0), used to evaluate an always-scanned signature whose
    /// atoms didn't hit this buffer without re-scanning its indexable body subsigs.
    pub fn empty() -> Self {
        SubHits {
            subsigs: &[],
            off_starts: &[],
            offsets: &[],
            base: 0,
        }
    }
}

impl SubHits<'_> {
    /// Offsets recorded for `(subsig, partno)`, or `None` if that part's atom did
    /// not hit. An empty slice means "overflowed — full scan". For an indexed part
    /// `None` means its required atom is absent, so the part (and thus the subsig)
    /// cannot match. `partno` is 0 for a non-gappy subsig.
    pub fn offsets_for(&self, subsig: usize, partno: usize) -> Option<&[u32]> {
        let key = ((subsig as u32) << 8) | partno as u32;
        self.subsigs.iter().position(|&s| s == key).map(|k| {
            let e = self.base + k;
            &self.offsets[self.off_starts[e] as usize..self.off_starts[e + 1] as usize]
        })
    }
}

impl LogCandidates {
    fn empty() -> Self {
        LogCandidates::List(LogCandidateSet {
            sigs: Vec::new(),
            entry_starts: vec![0],
            entry_subsig: Vec::new(),
            off_starts: vec![0],
            offsets: Vec::new(),
        })
    }

    /// Candidate count (`usize::MAX` for `All`), for profiling/logging.
    pub fn len(&self) -> usize {
        match self {
            LogCandidates::All => usize::MAX,
            LogCandidates::List(s) => s.sigs.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, LogCandidates::List(s) if s.sigs.is_empty())
    }

    /// Whether `sig` is among the atom-hit candidates (its `sigs` are sorted).
    pub fn contains(&self, sig: u32) -> bool {
        match self {
            LogCandidates::All => true,
            LogCandidates::List(s) => s.sigs.binary_search(&sig).is_ok(),
        }
    }

    /// Candidates carrying any threaded offsets (for profiling).
    pub fn threaded_count(&self) -> usize {
        match self {
            LogCandidates::All => 0,
            LogCandidates::List(s) => (0..s.sigs.len())
                .filter(|&k| s.entry_starts[k + 1] > s.entry_starts[k])
                .count(),
        }
    }

    /// Iterate `(lsig_index, per-subsig hit offsets)`. Empty for `All`.
    pub fn iter(&self) -> impl Iterator<Item = (u32, SubHits<'_>)> + '_ {
        let set = match self {
            LogCandidates::All => None,
            LogCandidates::List(s) => Some(s),
        };
        set.into_iter().flat_map(|s| {
            s.sigs.iter().enumerate().map(move |(k, &sig)| {
                let es = s.entry_starts[k] as usize;
                let ee = s.entry_starts[k + 1] as usize;
                (
                    sig,
                    SubHits {
                        subsigs: &s.entry_subsig[es..ee],
                        off_starts: &s.off_starts,
                        offsets: &s.offsets,
                        base: es,
                    },
                )
            })
        })
    }
}

/// Candidate signatures for a buffer, each carrying the buffer offsets where its
/// prefilter atom occurred. Stored as a CSR: for candidate `k`,
/// `offsets[off_starts[k]..off_starts[k+1]]` are its atom offsets. An **empty
/// span means "no threaded offsets — scan this signature the full way"** (an
/// atomless always-signature, or one whose offsets overflowed the cap). A
/// non-empty span lists every offset where the atom occurs, so verification is
/// complete when restricted to them.
pub struct CandidateSet {
    sigs: Vec<u32>,
    off_starts: Vec<u32>,
    offsets: Vec<u32>,
}

impl CandidateSet {
    fn empty() -> Self {
        CandidateSet {
            sigs: Vec::new(),
            off_starts: vec![0],
            offsets: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    /// Number of candidates that carry threaded offsets (non-empty span); the
    /// rest fall back to a full scan. For profiling only.
    pub fn threaded_count(&self) -> usize {
        (0..self.sigs.len())
            .filter(|&k| self.off_starts[k + 1] > self.off_starts[k])
            .count()
    }

    /// Iterate `(signature_index, atom_offsets)`. An empty offsets slice means
    /// "full scan this signature".
    pub fn iter(&self) -> impl Iterator<Item = (u32, &[u32])> + '_ {
        self.sigs.iter().enumerate().map(move |(k, &sig)| {
            let s = self.off_starts[k] as usize;
            let e = self.off_starts[k + 1] as usize;
            (sig, &self.offsets[s..e])
        })
    }
}

/// Which signatures to evaluate for a buffer.
pub enum Candidates {
    All,
    List(CandidateSet),
}

impl Candidates {
    /// Candidate count (`usize::MAX` sentinel for `All`), for profiling/logging.
    pub fn len(&self) -> usize {
        match self {
            Candidates::All => usize::MAX,
            Candidates::List(set) => set.len(),
        }
    }

    /// Candidates carrying threaded offsets (vs full-scan), for profiling.
    pub fn threaded_count(&self) -> usize {
        match self {
            Candidates::All => 0,
            Candidates::List(set) => set.threaded_count(),
        }
    }
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
    /// Lowercased first byte of every indexed nocase atom. A nocase atom can only
    /// match at a position whose (lowercased) byte is one of these, so if the
    /// buffer contains none of them the entire nocase pass — including the O(n)
    /// lowercased-buffer allocation — can be skipped with no risk of a missed
    /// match. Indexed by byte value. (Nocase atoms are NOT always alphabetic:
    /// `longest_nocase_run` folds any fixed byte, so digit/punctuation atoms
    /// exist — this is why an "is there a letter?" guard would be unsafe.)
    nocase_first_bytes: [bool; 256],
    ext_always: Vec<u32>,
    /// Logical signatures that cannot be gated by an atom (a non-indexable subsig —
    /// e.g. an `OR` branch that is a PCRE — could satisfy the expression on its
    /// own), so they are full-scanned on every buffer. Kept small by the gating
    /// analysis in `build`.
    log_always: Vec<u32>,
}

impl AtomPrefilter {
    /// Resident heap bytes, broken down, for `--mem-stats` profiling.
    pub fn mem_report(&self) -> String {
        let ac = self.ac.as_ref().map_or(0, |a| a.heap_bytes());
        let ac_nc = self.ac_nocase.as_ref().map_or(0, |a| a.heap_bytes());
        let v = |n: usize, sz: usize| n * sz;
        let csr = v(self.atom_starts.len(), 4)
            + v(self.sig_refs.len(), 8)
            + v(self.atom_starts_nocase.len(), 4)
            + v(self.sig_refs_nocase.len(), 8);
        let always = v(self.ext_always.len(), 4) + v(self.log_always.len(), 4);
        let mb = |b: usize| b as f64 / (1024.0 * 1024.0);
        format!(
            "ac={:.1}MB ac_nocase={:.1}MB csr(sig_refs+starts)={:.1}MB always/gates={:.1}MB | atoms={} nocase_atoms={} sig_refs={} sig_refs_nc={}",
            mb(ac), mb(ac_nc), mb(csr), mb(always),
            self.num_atoms, self.num_atoms_nocase, self.sig_refs.len(), self.sig_refs_nocase.len()
        )
    }
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
            nocase_first_bytes: [false; 256],
            ext_always: Vec::new(),
            log_always: Vec::new(),
        }
    }

    /// Logical signatures that must be evaluated on every buffer (no atom gates
    /// them — see `log_always`).
    pub fn log_always(&self) -> &[u32] {
        &self.log_always
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
        enum Atom {
            Exact(Vec<u8>),
            Nocase(Vec<u8>),
        }
        fn pattern_atom(p: &crate::pattern::Pattern) -> Option<Atom> {
            if let Some(a) = p.required_atom() {
                if usable(&a) {
                    return Some(Atom::Exact(a));
                }
            }
            // `required_atom_nocase` is recomputed on demand (owned) — it's only
            // ever read here at build time, so the bytes cost no resident memory.
            if let Some(a) = p.required_atom_nocase() {
                if usable(&a) {
                    return Some(Atom::Nocase(a));
                }
            }
            None
        }
        // The atoms to index for one pattern. A gappy pattern (`partno`) is indexed
        // by EVERY one of its gap-free parts' atoms — all in the single AC — so the
        // scanner can verify each part at its own AC-found offsets and stitch them
        // (ClamAV's part matching). `None` if the pattern isn't fully indexable: a
        // gappy pattern is only indexable when EVERY part has a usable atom (every
        // part must match, so any atom-less part would let it match unseen).
        fn pattern_atoms(p: &crate::pattern::Pattern) -> Option<Vec<(usize, Atom)>> {
            if !p.has_gap() {
                return pattern_atom(p).map(|a| vec![(0, a)]);
            }
            let mut atoms = Vec::new();
            for (pi, (part, _)) in p.gap_parts().iter().enumerate() {
                if part.instructions.is_empty() {
                    continue; // empty part (leading/trailing gap) — no atom needed
                }
                atoms.push((pi, pattern_atom(part)?));
            }
            (!atoms.is_empty()).then_some(atoms)
        }
        fn evaluable_offset(anchor: &OffsetAnchor) -> bool {
            !matches!(
                anchor,
                OffsetAnchor::Unsupported(_)
                    | OffsetAnchor::MacroGroup(_)
                    | OffsetAnchor::VersionInfo
            )
        }

        // --- Extended signatures: match if ANY pattern matches. ---
        for (si, sig) in db.extended.iter().enumerate() {
            let mut atoms: Vec<Atom> = Vec::with_capacity(sig.patterns.len());
            let mut atomless = sig.patterns.is_empty();
            for p in &sig.patterns {
                // Extended sigs key by signature only; index ONE atom per pattern
                // (a gappy extended sig is verified by the inline matcher at that
                // atom's offsets — part-by-part offmatrix is the logical path).
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
                        Atom::Exact(a) => entries.push((short_atom(&a).into(), ext_ref(si))),
                        Atom::Nocase(a) => {
                            entries_nocase.push((short_atom(&a).into(), ext_ref(si)))
                        }
                    }
                }
            }
        }

        // --- Logical signatures (ClamAV-style per-subsignature indexing): index
        // EVERY indexable subsignature's atoms keyed to `(lsig, subsig)`, so the one
        // AC pass records, per candidate, the offsets where each subsig's atom
        // occurred and each subsig is verified only there. A sig is `log_always`
        // (full-scanned every buffer) only when its expression could be satisfied
        // *without* any indexable subsig — e.g. an `OR` branch that is a PCRE — so
        // an atom hit isn't necessary. `subsig_indexable` (a body subsig whose every
        // variant has a usable atom and an evaluable offset) is mirrored exactly by
        // the scanner, so the per-subsig offset threading lines up. ---
        let probe_present = 1usize << 30;
        for (si, sig) in db.logical.iter().enumerate() {
            let n = sig.subsignatures.len();
            let mut indexable_mask = vec![false; n];
            // `(subsig, partno, atom)` for every indexable part of every body subsig.
            let mut subsig_atoms: Vec<(usize, usize, Atom)> = Vec::new();
            for (i, subsig) in sig.subsignatures.iter().enumerate() {
                let Subsignature::Body { offset, patterns } = subsig else {
                    continue;
                };
                let default_offset = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&default_offset);
                if patterns.is_empty() || !evaluable_offset(&offset.anchor) {
                    continue;
                }
                // Indexable iff EVERY variant is fully indexable (gappy variants
                // require every part to have an atom — see `pattern_atoms`).
                let mut atoms: Vec<(usize, Atom)> = Vec::with_capacity(patterns.len());
                let mut ok = true;
                for p in patterns {
                    match pattern_atoms(p) {
                        Some(a) => atoms.extend(a),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && !atoms.is_empty() {
                    indexable_mask[i] = true;
                    for (partno, a) in atoms {
                        subsig_atoms.push((i, partno, a));
                    }
                }
            }

            // Gateable iff the expression is false when every indexable subsig is
            // absent (non-indexable subsigs assumed present): then an atom hit on
            // some indexed subsig is necessary for a match, so when none hit the
            // signature provably cannot match and is safely skipped.
            let gateable = !subsig_atoms.is_empty() && {
                let mut probe = vec![probe_present; n];
                for (i, &on) in indexable_mask.iter().enumerate() {
                    if on {
                        probe[i] = 0;
                    }
                }
                !sig.expression.eval(&probe).matched
            };

            // Index every indexable subsig's atoms keyed `(sig, subsig)` — for
            // gateable AND always sigs. For an always sig (one whose expression a
            // non-indexable subsig could satisfy alone) this still lets its body
            // subsigs verify cheaply at their atom offsets; it's merely *also*
            // evaluated when none of its atoms hit, to check its non-indexable
            // branch (`log_always`).
            for (subsig, partno, a) in subsig_atoms {
                match a {
                    Atom::Exact(a) => {
                        entries.push((short_atom(&a).into(), log_ref(si, subsig, partno)))
                    }
                    Atom::Nocase(a) => {
                        entries_nocase.push((short_atom(&a).into(), log_ref(si, subsig, partno)))
                    }
                }
            }
            if !gateable {
                log_always.push(si as u32);
            }
        }

        // Distinct (already-lowercased) first bytes of every nocase atom, for the
        // cheap "could any nocase atom possibly match this buffer?" guard in
        // `candidates()`. Computed before `entries_nocase` is consumed below.
        let mut nocase_first_bytes = [false; 256];
        for (atom, _) in &entries_nocase {
            if let Some(&b) = atom.first() {
                nocase_first_bytes[b as usize] = true;
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
            nocase_first_bytes,
            ext_always,
            log_always,
        }
    }

    /// Extended candidate set + logical per-subsignature candidates for `data`,
    /// from one AC pass (plus the nocase pass). Extended carries per-signature atom
    /// offsets; logical carries per-`(sig, subsig)` offsets (`LogCandidates`).
    pub fn candidates(&self, data: &[u8]) -> (Candidates, LogCandidates) {
        if self.ac.is_none() && self.ac_nocase.is_none() {
            return (Candidates::All, LogCandidates::All);
        }

        let mut ext_hits: Vec<(u32, u32)> = Vec::new();
        let mut log_hits: Vec<(u64, u32)> = Vec::new(); // (sig<<8|subsig, offset)

        if let Some(ac) = self.ac.as_ref() {
            collect_hits(
                ac,
                data,
                self.num_atoms,
                &self.atom_starts,
                &self.sig_refs,
                &mut ext_hits,
                &mut log_hits,
            );
        }

        if let Some(ac_nocase) = self.ac_nocase.as_ref() {
            // `nocase` atoms were case-folded to lowercase at build time, so they
            // must be matched against a lowercased copy of the buffer. Skip the
            // O(n) allocation only when the buffer contains NO byte that could
            // begin a nocase atom — a precise, correctness-preserving guard.
            // (A naive "has an ASCII letter?" test would be WRONG: nocase atoms
            // can be all digits/punctuation, so a letterless-but-digit buffer
            // must still be scanned. See `nocase_first_bytes`.)
            if data
                .iter()
                .any(|&b| self.nocase_first_bytes[b.to_ascii_lowercase() as usize])
            {
                let lowered: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
                collect_hits(
                    ac_nocase,
                    &lowered,
                    self.num_atoms_nocase,
                    &self.atom_starts_nocase,
                    &self.sig_refs_nocase,
                    &mut ext_hits,
                    &mut log_hits,
                );
            }
        }

        let ext = build_candidate_set(ext_hits, &self.ext_always);
        let log = build_log_candidates(log_hits);
        (Candidates::List(ext), log)
    }
}

/// Run one Aho-Corasick pass over `haystack` and append `(sig_index, offset)`
/// pairs for **every** atom occurrence (offset = where the atom starts, i.e.
/// where the signature's required literal starts) into `ext_hits`/`log_hits`.
///
/// Recording all occurrences (not just the first) is what makes offset threading
/// complete. To bound memory when a short atom is extremely common, each atom is
/// capped at `CAP_PER_ATOM` recorded offsets; on overflow it emits one
/// `OFFSET_OVERFLOW` sentinel for its signatures so they fall back to a full scan.
fn collect_hits(
    ac: &DoubleArrayAhoCorasick<u32>,
    haystack: &[u8],
    num_atoms: usize,
    atom_starts: &[u32],
    sig_refs: &[u64],
    ext_hits: &mut Vec<(u32, u32)>,
    log_hits: &mut Vec<(u64, u32)>,
) {
    let mut counts = vec![0u32; num_atoms];
    for m in ac.find_overlapping_iter(haystack) {
        let id = m.value() as usize;
        if counts[id] > CAP_PER_ATOM {
            continue; // overflow sentinel already emitted for this atom
        }
        counts[id] += 1;
        let off = if counts[id] > CAP_PER_ATOM {
            OFFSET_OVERFLOW
        } else {
            m.start() as u32
        };
        let start = atom_starts[id] as usize;
        let end = atom_starts[id + 1] as usize;
        for &r in &sig_refs[start..end] {
            if r & LOG_FLAG != 0 {
                // Sort key groups hits by sig, then by `(subsig, partno)` (the low 16
                // bits), so `build_log_candidates` produces per-part offset lists.
                let (sig, subsig, partno) = log_unpack(r);
                let key = ((sig as u64) << 16) | ((subsig as u64) << 8) | partno as u64;
                log_hits.push((key, off));
            } else {
                ext_hits.push((r as u32, off));
            }
        }
    }
}

/// Group per-`(sig, subsig, partno)` logical hits into `LogCandidates`. `key =
/// sig<<16 | subsig<<8 | partno`; each `(subsig, partno)` becomes one entry keyed by
/// its low 16 bits. An `OFFSET_OVERFLOW` sentinel (or more than `MAX_OFFSETS_PER_SIG`
/// offsets) collapses that part's offsets to an empty span, meaning "full scan".
fn build_log_candidates(mut hits: Vec<(u64, u32)>) -> LogCandidates {
    if hits.is_empty() {
        return LogCandidates::empty();
    }
    hits.sort_unstable();
    hits.dedup();

    let mut sigs: Vec<u32> = Vec::new();
    let mut entry_starts: Vec<u32> = vec![0];
    let mut entry_subsig: Vec<u32> = Vec::new();
    let mut off_starts: Vec<u32> = vec![0];
    let mut offsets: Vec<u32> = Vec::new();

    let mut i = 0usize;
    while i < hits.len() {
        let sig = (hits[i].0 >> 16) as u32;
        while i < hits.len() && (hits[i].0 >> 16) as u32 == sig {
            let key = hits[i].0;
            let subpart = (key & 0xffff) as u32; // subsig<<8 | partno
            let base = offsets.len();
            let mut overflow = false;
            while i < hits.len() && hits[i].0 == key {
                let off = hits[i].1;
                if off == OFFSET_OVERFLOW {
                    overflow = true;
                } else if !overflow {
                    offsets.push(off);
                }
                i += 1;
            }
            if overflow || offsets.len() - base > MAX_OFFSETS_PER_SIG {
                offsets.truncate(base); // empty span → full scan this part
            }
            entry_subsig.push(subpart);
            off_starts.push(offsets.len() as u32);
        }
        sigs.push(sig);
        entry_starts.push(entry_subsig.len() as u32);
    }

    LogCandidates::List(LogCandidateSet {
        sigs,
        entry_starts,
        entry_subsig,
        off_starts,
        offsets,
    })
}

/// Group `(sig, offset)` hits by signature into a CSR `CandidateSet`, merging in
/// the atomless `always` signatures (which get an empty offset span → full scan).
/// A signature whose atom overflowed, or that accumulated more than
/// `MAX_OFFSETS_PER_SIG` offsets, also gets an empty span (full scan) to bound
/// memory. Signatures stay sorted and de-duplicated.
fn build_candidate_set(mut hits: Vec<(u32, u32)>, always: &[u32]) -> CandidateSet {
    if hits.is_empty() && always.is_empty() {
        return CandidateSet::empty();
    }
    hits.sort_unstable();
    hits.dedup();

    let mut always_sorted = always.to_vec();
    always_sorted.sort_unstable();
    always_sorted.dedup();

    let mut sigs: Vec<u32> = Vec::new();
    let mut off_starts: Vec<u32> = vec![0];
    let mut offsets: Vec<u32> = Vec::new();

    let mut hi = 0usize;
    let mut ai = 0usize;
    loop {
        let next_hit = hits.get(hi).map(|&(s, _)| s);
        let next_always = always_sorted.get(ai).copied();
        let take_hit = match (next_hit, next_always) {
            (Some(h), Some(a)) => h <= a,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };

        if take_hit {
            let sig = next_hit.unwrap();
            let base = offsets.len();
            let mut overflow = false;
            while hi < hits.len() && hits[hi].0 == sig {
                let off = hits[hi].1;
                if off == OFFSET_OVERFLOW {
                    overflow = true;
                } else if !overflow {
                    offsets.push(off);
                }
                hi += 1;
            }
            // Too many offsets → drop them and full-scan this signature.
            if overflow || offsets.len() - base > MAX_OFFSETS_PER_SIG {
                offsets.truncate(base);
            }
            // Hit-sigs and always-sigs are disjoint, but de-dupe defensively.
            if next_always == Some(sig) {
                ai += 1;
            }
            sigs.push(sig);
            off_starts.push(offsets.len() as u32);
        } else {
            let sig = next_always.unwrap();
            ai += 1;
            sigs.push(sig); // atomless → empty span → full scan
            off_starts.push(offsets.len() as u32);
        }
    }

    CandidateSet {
        sigs,
        off_starts,
        offsets,
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
