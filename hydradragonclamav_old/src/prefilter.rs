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

/// Per-logical-signature gating info: which body subsignature to evaluate first
/// (the cutoff), and whether the prefilter indexed *exactly* that subsignature
/// (so the candidate's threaded offsets line up with it and can be used to verify
/// it). When `threadable` is false the gate is still evaluated first for the
/// early cutoff, but with a full scan (no offsets correspond to it).
#[derive(Clone, Copy, Debug)]
pub struct GateInfo {
    pub subsig: u32,
    pub threadable: bool,
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
    log_always: Vec<u32>,
    /// Per logical signature (indexed by logical sig index): the gating subsig
    /// and whether its offsets are threadable. `None` when no single subsig gates
    /// the expression (pure OR / matches-at-zero).
    log_gates: Vec<Option<GateInfo>>,
    /// Per logical signature: `true` when EVERY subsignature's atoms were indexed
    /// (the OR-fallback case), so the candidate's offsets are the union of all
    /// subsig atom occurrences. The scanner can then restrict each subsig's scan to
    /// windows around those offsets instead of rescanning the whole buffer.
    log_all_indexed: Vec<bool>,
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
        let always = v(self.ext_always.len(), 4)
            + v(self.log_always.len(), 4)
            + v(self.log_gates.len(), std::mem::size_of::<Option<GateInfo>>());
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
            log_gates: Vec::new(),
            log_all_indexed: Vec::new(),
        }
    }

    /// Whether every subsignature's atoms were indexed for logical sig `si`, so its
    /// candidate offsets are the union of all subsig atom occurrences.
    pub fn logical_all_indexed(&self, si: usize) -> bool {
        self.log_all_indexed.get(si).copied().unwrap_or(false)
    }

    /// The gating subsignature for logical signature `si`, if any.
    pub fn logical_gate(&self, si: usize) -> Option<GateInfo> {
        self.log_gates.get(si).copied().flatten()
    }

    /// Build the prefilter from a loaded database.
    /// Build the prefilter. The Aho-Corasick automata are always built in memory
    /// (no on-disk cache); the one-time build high-water-mark is returned to the OS
    /// by `trim_working_set` after loading.
    pub fn build(db: &Database) -> Self {
        let mut entries: Vec<(Box<[u8]>, u64)> = Vec::new();
        let mut entries_nocase: Vec<(Box<[u8]>, u64)> = Vec::new();
        let mut ext_always: Vec<u32> = Vec::new();
        let mut log_always: Vec<u32> = Vec::new();
        let mut log_gates: Vec<Option<GateInfo>> = Vec::with_capacity(db.logical.len());
        let mut log_all_indexed: Vec<bool> = Vec::with_capacity(db.logical.len());

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

        // --- Logical signatures: index ONE *required* subsignature's atoms, and
        // make that exact subsignature the gate (so its threaded offsets line up
        // for verification). ---
        let probe_present = 1usize << 30;
        for (si, sig) in db.logical.iter().enumerate() {
            let n = sig.subsignatures.len();
            if sig.expression.eval(&vec![0usize; n]).matched {
                // Can fire with nothing present → nothing to gate or index on.
                log_always.push(si as u32);
                log_gates.push(None);
                log_all_indexed.push(false);
                continue;
            }

            // Best *indexable* required subsig: every variant has a usable atom,
            // offset is evaluable, longest atom (most selective). Its atoms are
            // indexed and it becomes the threadable gate.
            let mut best_index: Option<(usize, usize, Vec<Atom>)> = None; // (max_len, idx, atoms)
            // Best cutoff-only gate: any required subsig with an evaluable offset,
            // preferring a longer exact atom. Used when nothing is indexable, so
            // the early cutoff still applies (no offsets to thread).
            let mut best_gate: Option<(usize, usize)> = None; // (exact_atom_len, idx)

            // The required-subsig probe below maxes sibling counts, which is only
            // sound for a monotone expression. With a non-monotone Compare (`=N`,
            // `<N`, `<=N`) the probe can wrongly flag a subsig as required and drop
            // the candidate (false negative). For such signatures we skip
            // single-subsig gating entirely and fall through to the OR-index-all /
            // `log_always` path (which only relies on the all-absent check above).
            let monotone = !sig.expression.has_nonmonotone_compare();

            for i in 0..(if monotone { n } else { 0 }) {
                let Subsignature::Body { offset, patterns } = &sig.subsignatures[i] else {
                    continue;
                };
                let default_offset = OffsetSpec::any();
                let offset = offset.as_deref().unwrap_or(&default_offset);
                if patterns.is_empty() || !evaluable_offset(&offset.anchor) {
                    continue;
                }
                // Required? (expression false when only this subsig is absent.)
                let mut probe = vec![probe_present; n];
                probe[i] = 0;
                if sig.expression.eval(&probe).matched {
                    continue;
                }

                let exact_len = patterns
                    .iter()
                    .filter_map(|p| p.required_atom().map(|a| a.len()))
                    .max()
                    .unwrap_or(0);
                if best_gate.map_or(true, |(bl, _)| exact_len > bl) {
                    best_gate = Some((exact_len, i));
                }

                // Indexable only if EVERY variant has a usable atom — otherwise a
                // variant could match without any indexed atom appearing, and the
                // prefilter would wrongly skip the signature.
                let mut atoms: Vec<Atom> = Vec::with_capacity(patterns.len());
                let mut all = true;
                for p in patterns {
                    match pattern_atom(p) {
                        Some(a) => atoms.push(a),
                        None => {
                            all = false;
                            break;
                        }
                    }
                }
                if !all {
                    continue;
                }
                let max_len = atoms
                    .iter()
                    .map(|a| match a {
                        Atom::Exact(b) => b.len(),
                        Atom::Nocase(b) => b.len(),
                    })
                    .max()
                    .unwrap_or(0);
                if best_index.as_ref().map_or(true, |(bl, _, _)| max_len > *bl) {
                    best_index = Some((max_len, i, atoms));
                }
            }

            // OR-type fallback: no single subsig is *required* (e.g. `0|1|2`), so
            // nothing can gate the expression. But if EVERY subsignature is an
            // indexable body (all variants have a usable atom and an evaluable
            // offset), index them ALL: the signature then becomes a candidate only
            // when one of its branch atoms appears, instead of being evaluated on
            // every buffer (`log_always`). This is the dominant cost on logical-
            // heavy databases — thousands of OR signatures otherwise run on every
            // scan. Safe because the expression is false when all subsigs are absent
            // (checked above), so if no indexed atom occurs it provably can't match.
            // No single gate offset applies (the hit may be any branch), so these
            // carry the cutoff-only `best_gate` if any, never a threadable gate.
            let or_atoms: Option<Vec<Atom>> = if best_index.is_none() {
                let mut acc: Vec<Atom> = Vec::new();
                let mut all = true;
                for i in 0..n {
                    let Subsignature::Body { offset, patterns } = &sig.subsignatures[i] else {
                        all = false;
                        break;
                    };
                    let default_offset = OffsetSpec::any();
                    let offset = offset.as_deref().unwrap_or(&default_offset);
                    if patterns.is_empty() || !evaluable_offset(&offset.anchor) {
                        all = false;
                        break;
                    }
                    for p in patterns {
                        match pattern_atom(p) {
                            Some(a) => acc.push(a),
                            None => {
                                all = false;
                                break;
                            }
                        }
                    }
                    if !all {
                        break;
                    }
                }
                (all && !acc.is_empty()).then_some(acc)
            } else {
                None
            };

            match (best_index, or_atoms) {
                (Some((_, idx, atoms)), _) => {
                    for a in atoms {
                        match a {
                            Atom::Exact(a) => entries.push((short_atom(&a).into(), log_ref(si))),
                            Atom::Nocase(a) => {
                                entries_nocase.push((short_atom(&a).into(), log_ref(si)))
                            }
                        }
                    }
                    log_gates.push(Some(GateInfo {
                        subsig: idx as u32,
                        threadable: true,
                    }));
                    log_all_indexed.push(false);
                }
                (None, Some(atoms)) => {
                    for a in atoms {
                        match a {
                            Atom::Exact(a) => entries.push((short_atom(&a).into(), log_ref(si))),
                            Atom::Nocase(a) => {
                                entries_nocase.push((short_atom(&a).into(), log_ref(si)))
                            }
                        }
                    }
                    // Indexed as an OR candidate set — NOT always-scanned.
                    log_gates.push(best_gate.map(|(_, idx)| GateInfo {
                        subsig: idx as u32,
                        threadable: false,
                    }));
                    log_all_indexed.push(true);
                }
                (None, None) => {
                    log_always.push(si as u32);
                    log_gates.push(best_gate.map(|(_, idx)| GateInfo {
                        subsig: idx as u32,
                        threadable: false,
                    }));
                    log_all_indexed.push(false);
                }
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
            log_gates,
            log_all_indexed,
        }
    }

    /// Candidate (extended, logical) signature sets for `data`, each with the
    /// atom offsets to thread into verification.
    pub fn candidates(&self, data: &[u8]) -> (Candidates, Candidates) {
        if self.ac.is_none() && self.ac_nocase.is_none() {
            return (Candidates::All, Candidates::All);
        }

        let mut ext_hits: Vec<(u32, u32)> = Vec::new();
        let mut log_hits: Vec<(u32, u32)> = Vec::new();

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
        let log = build_candidate_set(log_hits, &self.log_always);
        (Candidates::List(ext), Candidates::List(log))
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
    log_hits: &mut Vec<(u32, u32)>,
) {
    let mut counts = vec![0u32; num_atoms];
    for m in ac.find_overlapping_iter(haystack) {
        let id = m.value() as usize;
        let c = &mut counts[id];
        if *c >= CAP_PER_ATOM {
            // First occurrence past the cap: emit ONE overflow sentinel,
            // then suppress all further occurrences for this atom.
            if *c == CAP_PER_ATOM {
                *c += 1;
                let start = atom_starts[id] as usize;
                let end = atom_starts[id + 1] as usize;
                for &r in &sig_refs[start..end] {
                    if r & LOG_FLAG != 0 {
                        log_hits.push(((r & !LOG_FLAG) as u32, OFFSET_OVERFLOW));
                    } else {
                        ext_hits.push((r as u32, OFFSET_OVERFLOW));
                    }
                }
            }
            continue;
        }
        *c += 1;
        let off = m.start() as u32;
        let start = atom_starts[id] as usize;
        let end = atom_starts[id + 1] as usize;
        for &r in &sig_refs[start..end] {
            if r & LOG_FLAG != 0 {
                log_hits.push(((r & !LOG_FLAG) as u32, off));
            } else {
                ext_hits.push((r as u32, off));
            }
        }
    }
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
            while hi < hits.len() && hits[hi].0 == sig {
                let off = hits[hi].1;
                if off != OFFSET_OVERFLOW {
                    offsets.push(off);
                }
                hi += 1;
            }
            // Too many offsets → drop them and full-scan this signature.
            if offsets.len() - base > MAX_OFFSETS_PER_SIG {
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
    // Build the double-array AC in memory from the sorted atoms. This spikes a large
    // transient during construction; it's returned to the OS by `trim_working_set`
    // after loading. (No on-disk cache: serializing it only shaved the trie's own
    // build transient, but the load-time RAM peak is dominated by the other engines
    // — YARA-X, ML, ClamAV — loading at the same time, so it wasn't worth the files.)
    let ac: Option<DoubleArrayAhoCorasick<u32>> = if atoms.is_empty() {
        None
    } else {
        DoubleArrayAhoCorasick::<u32>::new(&atoms).ok()
    };
    drop(atoms);
    drop(entries);
    (ac, num_atoms, atom_starts, sig_refs)
}
