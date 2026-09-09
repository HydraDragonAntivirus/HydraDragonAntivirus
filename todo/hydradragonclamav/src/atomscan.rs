use crate::atomfilter::{AtomFilterDb, PerTarget, SlotId, SubsigSlot};
use crate::atomfilter::{ExtSlot, SlotDef};
use crate::pattern::Pattern;
use daachorse::clamav_fast::ClamavFastScanner;

/// Cached CPU count, capped at 4. `std::thread::available_parallelism()` is not
/// free on Android: it probes CPU affinity and cgroup-v2 CPU-quota files under
/// `/sys/fs/cgroup`, which the app sandbox is denied `search` on — every call
/// produces an SELinux `avc: denied { search } … cgroup2` audit line. The atom
/// sweep used to call it up to three times per scanned buffer (once per pass,
/// per exact/nocase), so an APK with hundreds of nested entries flooded logcat
/// with denials AND paid the probe cost repeatedly. The value can't change over
/// a process's lifetime, so resolve it once and reuse it.
fn worker_count() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 4);
    CACHED.store(n, Ordering::Relaxed);
    n
}

/// Per-slot hit counts (and last-seen match start offset) for one buffer.
pub struct SlotCounts<'a> {
    counts: &'a [u32],
    last_offset: &'a [u32],
}

impl SlotCounts<'_> {
    pub fn get(&self, slot: SlotId) -> u32 {
        self.counts[slot as usize]
    }

    pub fn last_offset(&self, slot: SlotId) -> Option<usize> {
        let o = self.last_offset[slot as usize];
        (o != u32::MAX).then_some(o as usize)
    }
}

/// Reusable per-thread scratch buffers for the atom-filter sweep.
///
/// These arrays are sized to the signature database (hundreds of thousands of
/// slots) and are fully reset at the start of every `scan`. Previously they
/// were owned by a short-lived `AtomFilterScanner` that was allocated fresh for
/// every extracted buffer (`scan_context` → `AtomFilterScanner::new`), so an APK
/// with hundreds of nested files paid hundreds of large heap
/// allocations+deallocations proportional to the DB size. Holding the scratch
/// in a thread-local `AtomScratch` and reusing it across buffers keeps the
/// (unavoidable) per-buffer zeroing but eliminates the allocation churn.
pub struct AtomScratch {
    lowered_buf: Vec<u8>,
    value_remaining: Vec<u32>,
    saturated: Vec<u64>,
    counts: Vec<u32>,
    last_offset: Vec<u32>,
}

impl Default for AtomScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct AutomatonStats {
    daachorse_us: u64,
    daachorse_matches: u64,
    inner_iterations: u64,
    saturated_skip: u64,
    ft_skip: u64,
    saturated_count: u64,
    saturated_dec: u64,
    incremented: u64,
    inner_loop_us: u64,
}

/// Context for inline pattern verification during the dense DFA sweep.
///
/// When an atom matches at a position, the sweep can immediately call
/// `Pattern::match_at` at that position. If the full pattern matches, the
/// slot is marked verified — no separate `count_all` re-scan is needed.
/// This mirrors ClamAV's approach where the AC trie traversal and pattern
/// verification happen in a single pass (cf. `cli_ac_scanbuff` + `ac_findmatch`).
///
/// `slot_patterns[slot_id]` is the set of patterns to verify for that slot.
/// An empty slice means no verification (non-Body subsig or extended sig).
pub struct InlineVerifyCtx<'a, 'b> {
    pub(crate) slot_patterns: &'a [&'b [Pattern]],
    pub(crate) hay: &'b [u8],
}

impl InlineVerifyCtx<'_, '_> {
    /// Try to verify a pattern at the given position. Returns true if ANY
    /// pattern of this slot matches. Once a slot is verified, we don't
    /// re-verify it.
    fn try_verify(&self, slot_id: SlotId, start: usize, already: bool) -> bool {
        if already {
            return true;
        }
        let sid = slot_id as usize;
        if sid >= self.slot_patterns.len() {
            return false;
        }
        let patterns = self.slot_patterns[sid];
        for p in patterns {
            if p.match_at(self.hay, start).is_some() {
                return true;
            }
        }
        false
    }
}

impl AtomScratch {
    /// Allocate empty scratch. Buffers are grown/reset lazily on the first
    /// `scan` to match the database slot count, then reused across buffers.
    pub fn new() -> Self {
        AtomScratch {
            lowered_buf: Vec::new(),
            value_remaining: Vec::new(),
            saturated: Vec::new(),
            counts: Vec::new(),
            last_offset: Vec::new(),
        }
    }

    fn select_target<'b>(per_target: &'b [PerTarget], file_type_target: u32) -> &'b PerTarget {
        if file_type_target == 0 {
            return &per_target[0];
        }
        per_target
            .iter()
            .find(|pt| pt.target == file_type_target)
            .unwrap_or(&per_target[0])
    }

    /// Run the dense DFA on one contiguous byte slice with its own output
    /// buffers.  Used both single-threaded and as a per-chunk worker in
    /// `run_dense_parallel`.
    ///
    /// `data_offset`: the offset of `hay[0]` within the full data buffer
    /// (used to compute the absolute position for inline verification).
    #[allow(clippy::too_many_arguments)]
    fn run_dense_chunk(
        pma: &ClamavFastScanner<u32>,
        atom_to_slots: &[Box<[SlotId]>],
        slot_to_values: &[Box<[u32]>],
        slots: &[SlotDef],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
    ) {
        for m in pma.find_iter(hay) {
            out_stats.daachorse_matches += 1;
            let vi = m.value() as usize;
            if vi < atom_to_slots.len() && value_remaining[vi] != 0 {
                let start = m.start();
                for &slot_id in atom_to_slots[vi].iter() {
                    out_stats.inner_iterations += 1;
                    let st = slot_id as usize;
                    if (saturated[st >> 6] >> (st & 63)) & 1 == 1 {
                        out_stats.saturated_skip += 1;
                        continue;
                    }
                    let ft = slots[st].file_type_target;
                    if ft != 0 && ft != file_type_target {
                        out_stats.ft_skip += 1;
                        continue;
                    }
                    if counts[st] >= slots[st].threshold {
                        saturated[st >> 6] |= 1 << (st & 63);
                        out_stats.saturated_count += 1;
                        for &ref_vi in slot_to_values[st].iter() {
                            out_stats.saturated_dec += 1;
                            let rvi = ref_vi as usize;
                            if rvi < value_remaining.len() {
                                value_remaining[rvi] = value_remaining[rvi].saturating_sub(1);
                            }
                        }
                        continue;
                    }
                    counts[st] = counts[st].saturating_add(1);
                    last_offset[st] = last_offset[st].max(start as u32);
                    out_stats.incremented += 1;
                    // Inline verification: if the atom matched at `start`,
                    // try to verify the full pattern immediately (like
                    // ClamAV's ac_findmatch). Once verified, the slot
                    // won't need a separate count_all rescan.
                    // `abs_start = data_offset + start` is the position
                    // within the original full data buffer.
                    if let Some(vctx) = verify_ctx {
                        if st < verify_results.len() && !verify_results[st] {
                            if vctx.try_verify(slot_id, data_offset + start, false) {
                                verify_results[st] = true;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run the dense DFA on the whole slice (single-threaded path).
    ///
    /// `data_offset`: the offset of `hay[0]` within the full data buffer.
    fn run_dense_automaton(
        pt: &PerTarget,
        exact: bool,
        slots: &[SlotDef],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
    ) {
        let pma = Self::resolve_scanner(pt, exact);
        let pma = match pma {
            Some(p) => p,
            _ => return,
        };
        let t0 = std::time::Instant::now();
        Self::run_dense_chunk(
            pma,
            &pt.atom_to_slots,
            &pt.slot_to_values,
            slots,
            saturated,
            value_remaining,
            hay,
            file_type_target,
            counts,
            last_offset,
            out_stats,
            verify_ctx,
            verify_results,
            data_offset,
        );
        out_stats.daachorse_us = t0.elapsed().as_micros() as u64;
    }

    /// Resolve the scanner for a target (exact or nocase).
    fn resolve_scanner<'b>(pt: &'b PerTarget, exact: bool) -> Option<&'b ClamavFastScanner<u32>> {
        if exact {
            pt.exact.as_ref()
        } else {
            pt.nocase.as_ref()
        }
    }

    /// Run the daachorse DFA on `hay` in parallel chunks when the buffer is
    /// large enough to benefit.  Each thread processes a contiguous chunk with
    /// a small overlap so patterns that cross cut points are still detected.
    ///
    /// `data_offset`: the offset of `hay[0]` within the full data buffer.
    fn run_dense_parallel(
        pt: &PerTarget,
        exact: bool,
        slots: &[SlotDef],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        last_offset: &mut [u32],
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
    ) {
        let n_threads = worker_count();

        // Single-threaded fallback for small buffers or single-core systems.
        if n_threads <= 1 || hay.len() < 256 * 1024 {
            Self::run_dense_automaton(
                pt,
                exact,
                slots,
                &mut vec![0u64; (counts.len() + 63) / 64],
                &mut vec![0u32; pt.atom_to_slots.len()],
                hay,
                file_type_target,
                counts,
                last_offset,
                out_stats,
                verify_ctx,
                verify_results,
                data_offset,
            );
            return;
        }

        let pma = Self::resolve_scanner(pt, exact);
        let pma = match pma {
            Some(p) => p,
            _ => return,
        };
        let atom_to_slots = &pt.atom_to_slots;
        let slot_to_values = &pt.slot_to_values;

        // Cross-chunk overlap: daachorse detects patterns at their *ending*
        // position.  A pattern starting just before a cut point is only found
        // in the chunk that contains its end.  Overlap by 1024 bytes — far
        // longer than any ClamAV atom — so every pattern that could straddle
        // a boundary is found in the neighbouring chunk.
        const OVERLAP: usize = 1024;

        let chunk_size = (hay.len() + n_threads - 1) / n_threads;
        let t0 = std::time::Instant::now();

        // Per-thread private output.
        let mut thread_counts: Vec<Vec<u32>> =
            (0..n_threads).map(|_| vec![0u32; counts.len()]).collect();
        let mut thread_last: Vec<Vec<u32>> = (0..n_threads)
            .map(|_| vec![u32::MAX; last_offset.len()])
            .collect();
        let mut thread_sat: Vec<Vec<u64>> = (0..n_threads)
            .map(|_| vec![0u64; (counts.len() + 63) / 64])
            .collect();
        let mut thread_vr: Vec<Vec<u32>> = (0..n_threads)
            .map(|_| atom_to_slots.iter().map(|s| s.len() as u32).collect())
            .collect();

        // Per-thread verify results (only populated when verify_ctx is active).
        let n_slots = counts.len();
        let has_verify = verify_ctx.is_some();
        let mut thread_vfy: Vec<Vec<bool>> = if has_verify {
            (0..n_threads).map(|_| vec![false; n_slots]).collect()
        } else {
            (0..n_threads).map(|_| Vec::new()).collect()
        };

        let mut stats: Vec<AutomatonStats> =
            (0..n_threads).map(|_| AutomatonStats::default()).collect();

        std::thread::scope(|s| {
            let mut count_iter = thread_counts.iter_mut();
            let mut last_iter = thread_last.iter_mut();
            let mut sat_iter = thread_sat.iter_mut();
            let mut vr_iter = thread_vr.iter_mut();
            let mut stats_iter = stats.iter_mut();
            let mut vfy_iter = thread_vfy.iter_mut();

            for tid in 0..n_threads {
                let chunk_start = tid * chunk_size;
                if chunk_start >= hay.len() {
                    break;
                }
                let chunk_end = (chunk_start + chunk_size + OVERLAP).min(hay.len());
                let chunk = &hay[chunk_start..chunk_end];
                // Absolute offset of this chunk's first byte within the
                // full data buffer (for inline verification).
                let chunk_data_offset = data_offset + chunk_start;

                let counts = count_iter.next().unwrap();
                let last = last_iter.next().unwrap();
                let sat = sat_iter.next().unwrap();
                let vr = vr_iter.next().unwrap();
                let st = stats_iter.next().unwrap();
                let vfy = vfy_iter.next().unwrap();

                s.spawn(move || {
                    Self::run_dense_chunk(
                        pma,
                        atom_to_slots,
                        slot_to_values,
                        slots,
                        sat,
                        vr,
                        chunk,
                        file_type_target,
                        counts,
                        last,
                        st,
                        verify_ctx,
                        vfy,
                        chunk_data_offset,
                    );
                });
            }
        });

        // Merge per-thread results into the main arrays.
        for tid in 0..n_threads {
            out_stats.daachorse_matches += stats[tid].daachorse_matches;
            out_stats.inner_iterations += stats[tid].inner_iterations;
            out_stats.saturated_skip += stats[tid].saturated_skip;
            out_stats.ft_skip += stats[tid].ft_skip;
            out_stats.saturated_count += stats[tid].saturated_count;
            out_stats.saturated_dec += stats[tid].saturated_dec;
            out_stats.incremented += stats[tid].incremented;

            for i in 0..counts.len() {
                if thread_counts[tid][i] > 0 {
                    counts[i] = counts[i].saturating_add(thread_counts[tid][i]);
                    if thread_last[tid][i] != u32::MAX {
                        let global = tid * chunk_size + thread_last[tid][i] as usize;
                        if global < last_offset[i] as usize {
                            last_offset[i] = global as u32;
                        }
                    }
                }
            }

            // Merge verify results.
            if verify_ctx.is_some() {
                for i in 0..verify_results.len() {
                    if thread_vfy[tid][i] {
                        verify_results[i] = true;
                    }
                }
            }
        }

        out_stats.daachorse_us = t0.elapsed().as_micros() as u64;
    }

    fn scan_impl<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
    ) -> SlotCounts<'_> {
        let n_slots = db.slots.len();

        if self.counts.len() != n_slots {
            self.counts.resize(n_slots, 0);
            self.last_offset.resize(n_slots, u32::MAX);
        }
        let sat_words = (n_slots + 63) / 64;
        if self.saturated.len() != sat_words {
            self.saturated.resize(sat_words, 0);
        }
        for c in self.counts.iter_mut() {
            *c = 0;
        }
        for o in self.last_offset.iter_mut() {
            *o = u32::MAX;
        }
        for w in &mut self.saturated {
            *w = 0;
        }

        // Select target automaton.
        let pt = Self::select_target(&db.per_target, file_type_target);

        self.value_remaining.clear();
        for slots in pt.atom_to_slots.iter() {
            self.value_remaining.push(slots.len() as u32);
        }

        let mut exact_stats = AutomatonStats::default();
        let mut nocase_stats = AutomatonStats::default();

        // ── Shift-OR prefilter (exact-only hint) ──────────────────────
        let (exact_window, exact_offset) = match db.prefilter.search(data) {
            Some(start) if start < data.len() => (&data[start..], start),
            _ => (&data[0..0], 0),
        };

        // ── Exact automaton pass (data_offset = exact_offset) ────────
        if !exact_window.is_empty() {
            let n_threads = worker_count();
            if n_threads > 1 && exact_window.len() >= 256 * 1024 {
                Self::run_dense_parallel(
                    pt,
                    true,
                    &db.slots,
                    exact_window,
                    file_type_target,
                    &mut self.counts,
                    &mut self.last_offset,
                    &mut exact_stats,
                    verify_ctx,
                    verify_results,
                    exact_offset,
                );
            } else {
                Self::run_dense_automaton(
                    pt,
                    true,
                    &db.slots,
                    &mut self.saturated,
                    &mut self.value_remaining,
                    exact_window,
                    file_type_target,
                    &mut self.counts,
                    &mut self.last_offset,
                    &mut exact_stats,
                    verify_ctx,
                    verify_results,
                    exact_offset,
                );
            }
            if exact_offset > 0 {
                for o in self.last_offset.iter_mut() {
                    if *o != u32::MAX {
                        *o += exact_offset as u32;
                    }
                }
            }
        }

        // ── Nocase automaton pass (data_offset = 0) ──────────────────
        if pt.nocase.is_some() {
            let mut lowered = std::mem::take(&mut self.lowered_buf);
            if data.len() > lowered.len() {
                lowered.resize(data.len(), 0);
            }
            for (i, &b) in data.iter().enumerate() {
                lowered[i] = b.to_ascii_lowercase();
            }
            let n_threads = worker_count();
            if n_threads > 1 && data.len() >= 256 * 1024 {
                Self::run_dense_parallel(
                    pt,
                    false,
                    &db.slots,
                    &lowered[..data.len()],
                    file_type_target,
                    &mut self.counts,
                    &mut self.last_offset,
                    &mut nocase_stats,
                    verify_ctx,
                    verify_results,
                    0,
                );
            } else {
                Self::run_dense_automaton(
                    pt,
                    false,
                    &db.slots,
                    &mut self.saturated,
                    &mut self.value_remaining,
                    &lowered[..data.len()],
                    file_type_target,
                    &mut self.counts,
                    &mut self.last_offset,
                    &mut nocase_stats,
                    verify_ctx,
                    verify_results,
                    0,
                );
            }
            self.lowered_buf = lowered;
        }

        // ── Timing output (pt is still alive from the db borrow) ─────
        let total_us = exact_stats.daachorse_us + nocase_stats.daachorse_us;
        if total_us > 200_000 {
            let target_label = if pt.target == 0 {
                "full".to_string()
            } else {
                format!("tgt={}", pt.target)
            };
            let exact_info = if pt.exact.is_some() {
                format!(
                    "exact(daach={}us inner={}us matches={} iit={} sat_sk={} ft_sk={} dec={} inc={})",
                    exact_stats.daachorse_us,
                    exact_stats.inner_loop_us,
                    exact_stats.daachorse_matches,
                    exact_stats.inner_iterations,
                    exact_stats.saturated_skip,
                    exact_stats.ft_skip,
                    exact_stats.saturated_dec,
                    exact_stats.incremented,
                )
            } else {
                String::from("exact(none)")
            };
            let nocase_info = if pt.nocase.is_some() {
                format!(
                    "nocase(daach={}us inner={}us matches={} iit={} sat_sk={} ft_sk={} dec={} inc={})",
                    nocase_stats.daachorse_us,
                    nocase_stats.inner_loop_us,
                    nocase_stats.daachorse_matches,
                    nocase_stats.inner_iterations,
                    nocase_stats.saturated_skip,
                    nocase_stats.ft_skip,
                    nocase_stats.saturated_dec,
                    nocase_stats.incremented,
                )
            } else {
                String::from("nocase(none)")
            };
            eprintln!(
                "[ATOMSCAN] {} {}KB {} {}  exact_window={}",
                target_label,
                data.len() / 1024,
                exact_info,
                nocase_info,
                exact_window.len()
            );
        }

        SlotCounts {
            counts: &self.counts,
            last_offset: &self.last_offset,
        }
    }

    /// Run the atom sweep only (no inline verification).
    /// For inline verification, use [`scan_with_verify`].
    pub fn scan<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
    ) -> SlotCounts<'_> {
        self.scan_impl(db, data, file_type_target, None, &mut [])
    }

    /// Run the atom sweep with inline pattern verification.
    ///
    /// When an atom matches, the patterns associated with its slot are
    /// immediately verified at the match position (like ClamAV's
    /// `ac_findmatch`). Slots whose pattern is verified are set to `true`
    /// in `verify_results`, which the caller can use to skip the separate
    /// `count_all` re-scan.
    pub(crate) fn scan_with_verify<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
        verify_ctx: &InlineVerifyCtx,
        verify_results: &mut [bool],
    ) -> SlotCounts<'_> {
        for r in verify_results.iter_mut() {
            *r = false;
        }
        self.scan_impl(db, data, file_type_target, Some(verify_ctx), verify_results)
    }
}

pub fn ext_matched(ext_slot: ExtSlot, slots: &[SlotDef], counts: &SlotCounts) -> bool {
    match ext_slot {
        ExtSlot::AutoMatch => true,
        ExtSlot::Atom(id) => counts.get(id) >= slots[id as usize].threshold,
    }
}

pub fn logical_initial_counts_into(
    out: &mut [usize],
    sub_slots: &[SubsigSlot],
    slots: &[SlotDef],
    counts: &SlotCounts,
) -> usize {
    let n = sub_slots.len().min(out.len());
    for (i, s) in sub_slots[..n].iter().enumerate() {
        out[i] = match *s {
            SubsigSlot::Atom(id) => {
                let hits = counts.get(id);
                if hits >= slots[id as usize].threshold {
                    hits as usize
                } else {
                    0
                }
            }
            SubsigSlot::AutoMatch => 1,
            SubsigSlot::External => 0,
        };
    }
    n
}

pub fn logical_initial_counts(
    sub_slots: &[SubsigSlot],
    slots: &[SlotDef],
    counts: &SlotCounts,
) -> Vec<usize> {
    let mut out = vec![0; sub_slots.len()];
    logical_initial_counts_into(&mut out, sub_slots, slots, counts);
    out
}

pub fn subsig_anchor_offset(trigger: SubsigSlot, counts: &SlotCounts) -> usize {
    match trigger {
        SubsigSlot::Atom(id) => counts.last_offset(id).unwrap_or(0),
        SubsigSlot::AutoMatch | SubsigSlot::External => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomfilter_build::AtomFilterBuilder;
    use crate::database::Database;

    fn load_str(name: &str, contents: &str) -> Database {
        let mut files = std::collections::HashMap::new();
        files.insert(name.to_string(), contents.as_bytes().to_vec());
        Database::from_bytes_map(&files).0
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn extended_signature_promotes_on_atom_presence() {
        let hex = hex_of(b"HydraDragonTestAtom");
        let db = load_str("test.ndb", &format!("Test.Ndb.Sig:0:*:{hex}\n"));
        let afdb = AtomFilterBuilder::build(&db);
        let mut scanner = AtomScratch::new();

        let present = scanner.scan(&afdb, b"junk...HydraDragonTestAtom...junk", 0);
        assert!(ext_matched(afdb.ext_slot[0], &afdb.slots, &present));

        let absent = scanner.scan(&afdb, b"nothing interesting here at all", 0);
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &absent));
    }

    #[test]
    fn logical_and_expression_needs_both_subsigs() {
        let hex_a = hex_of(b"AtomAlphaLiteral");
        let hex_b = hex_of(b"AtomBravoLiteral");
        let db = load_str(
            "test.ldb",
            &format!("Test.Ldb.Sig;Target:0;0&1;{hex_a};{hex_b}\n"),
        );
        let afdb = AtomFilterBuilder::build(&db);
        let mut scanner = AtomScratch::new();
        let sub_slots = &afdb.log_subsig_slots[0];
        let expr = &db.logical[0].expression;

        let both = scanner.scan(&afdb, b"...AtomAlphaLiteral...AtomBravoLiteral...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &both);
        assert!(expr.eval(&counts).matched);

        let only_a = scanner.scan(&afdb, b"...AtomAlphaLiteral only...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &only_a);
        assert!(!expr.eval(&counts).matched);

        let neither = scanner.scan(&afdb, b"...nothing relevant...", 0);
        let counts = logical_initial_counts(sub_slots, &afdb.slots, &neither);
        assert!(!expr.eval(&counts).matched);
    }

    #[test]
    fn nocase_atom_matches_regardless_of_case() {
        let hex = hex_of(b"CaseSensitiveAtom");
        let db = load_str("test.ndb", &format!("Test.Ndb.Sig:0:*:{hex}\n"));
        let afdb = AtomFilterBuilder::build(&db);
        let mut scanner = AtomScratch::new();

        let wrong_case = scanner.scan(&afdb, b"...casesensitiveatom...", 0);
        assert!(!ext_matched(afdb.ext_slot[0], &afdb.slots, &wrong_case));
    }
}
