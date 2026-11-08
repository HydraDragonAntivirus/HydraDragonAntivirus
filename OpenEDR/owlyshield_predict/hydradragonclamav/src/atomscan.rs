use crate::atomfilter::{AtomFilterDb, PerTarget, SlotId, SubsigSlot};
use crate::atomfilter::{ExtSlot, SlotDef};

use daachorse::DoubleArrayAhoCorasick;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Cached CPU count, capped at 4. `std::thread::available_parallelism()` is not
/// free on Android: it probes CPU affinity and cgroup-v2 CPU-quota files under
/// `/sys/fs/cgroup`, which the app sandbox is denied `search` on — every call
/// produces an SELinux `avc: denied { search } … cgroup2` audit line. The atom
/// sweep used to call it up to three times per scanned buffer (once per pass,
/// per exact/nocase), so an APK with hundreds of nested entries flooded logcat
/// with denials AND paid the probe cost repeatedly. The value can't change over
/// a process's lifetime, so resolve it once and reuse it.
fn core_count() -> usize {
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1);
    CACHED.store(n, Ordering::Relaxed);
    n
}

static ACTIVE_SCANS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct ActiveScan;

impl ActiveScan {
    pub(crate) fn enter() -> Self {
        ACTIVE_SCANS.fetch_add(1, Ordering::Relaxed);
        ActiveScan
    }
}

impl Drop for ActiveScan {
    fn drop(&mut self) {
        ACTIVE_SCANS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn worker_count() -> usize {
    (core_count() / ACTIVE_SCANS.load(Ordering::Relaxed).max(1)).clamp(1, 4)
}

const LITERAL_HIT_LIMIT: u32 = 256;

fn anywhere(offset: Option<&crate::database::OffsetSpec>) -> bool {
    offset.is_none_or(|spec| matches!(spec.anchor, crate::database::OffsetAnchor::Any) && spec.max_shift.is_none())
}

fn only_literals(patterns: &[crate::pattern::Pattern]) -> bool {
    !patterns.is_empty() && patterns.iter().all(|p| p.pure_literal().is_some())
}

pub(crate) fn literal_slots(slots: &[SlotDef], db: &crate::database::Database) -> Vec<bool> {
    slots
        .iter()
        .map(|slot| match slot.target {
            crate::atomfilter::SlotTarget::Extended { sig_index } => db
                .extended
                .get(sig_index as usize)
                .is_some_and(|sig| anywhere(Some(&sig.offset)) && only_literals(&sig.patterns)),
            crate::atomfilter::SlotTarget::LogicalSubsig { sig_index, subsig_index } => db
                .logical
                .get(sig_index as usize)
                .and_then(|sig| sig.subsignatures.get(subsig_index as usize))
                .is_some_and(|sub| match sub {
                    crate::logical::Subsignature::Body { offset, patterns } => anywhere(offset.as_deref()) && only_literals(patterns),
                    _ => false,
                }),
        })
        .collect()
}

static SWEEP_WORKERS: Mutex<Vec<AtomScratch>> = Mutex::new(Vec::new());

fn take_sweep_workers(n: usize) -> Vec<AtomScratch> {
    let mut pool = SWEEP_WORKERS.lock().unwrap_or_else(|e| e.into_inner());
    let keep = pool.len().saturating_sub(n);
    let mut workers = pool.split_off(keep);
    drop(pool);
    workers.resize_with(n, AtomScratch::new);
    workers
}

fn return_sweep_workers(mut workers: Vec<AtomScratch>) {
    let mut pool = SWEEP_WORKERS.lock().unwrap_or_else(|e| e.into_inner());
    pool.append(&mut workers);
    pool.truncate(core_count());
}

/// Per-slot hit counts for one buffer.
pub struct SlotCounts<'a> {
    counts: &'a [u32],
    saturated: &'a [u64],
}

impl SlotCounts<'_> {
    pub fn get(&self, slot: SlotId) -> u32 {
        self.counts[slot as usize]
    }

    pub fn is_saturated(&self, slot: SlotId) -> bool {
        let st = slot as usize;
        (self.saturated[st >> 6] >> (st & 63)) & 1 == 1
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
    /// Per-slot inline verification results of the last scan.
    verify: Vec<bool>,
    /// Slots the last scan changed (counted or saturated; may repeat). The next
    /// scan resets only these instead of every slot of the DB, which cost a
    /// fixed few ms per buffer even for a 1 KB file.
    touched: Vec<u32>,
    /// `PerTarget::target` whose `value_remaining` this holds.
    vr_target: Option<u32>,
    /// The arrays are not known to be clean apart from `touched`: reset all.
    full_reset: bool,
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
/// The patterns of a slot are looked up only when one of its atoms hits: the
/// Body patterns of a logical subsignature; extended signatures and other
/// subsignature kinds are not verified here. (Building a slot -> patterns table
/// per buffer walked the whole signature DB on every scan, a fixed ~40 ms even
/// for a 1 KB file.)
pub struct InlineVerifyCtx<'a, 'b> {
    pub(crate) slots: &'a [SlotDef],
    pub(crate) logical: &'a [crate::logical::LogicalSignature],
    pub(crate) extended: &'a [crate::database::ExtendedSignature],
    pub(crate) literal_slots: &'a [bool],
    pub(crate) hay: &'b [u8],
}

impl InlineVerifyCtx<'_, '_> {
    fn is_literal(&self, slot: usize) -> bool {
        self.literal_slots.get(slot).copied().unwrap_or(false)
    }

    fn verify_literal(&self, slot_id: SlotId, start: usize, atom: &[u8]) -> bool {
        let Some(slot) = self.slots.get(slot_id as usize) else { return false };
        let patterns: &[crate::pattern::Pattern] = match slot.target {
            crate::atomfilter::SlotTarget::Extended { sig_index } => match self.extended.get(sig_index as usize) {
                Some(sig) => &sig.patterns,
                None => return false,
            },
            crate::atomfilter::SlotTarget::LogicalSubsig { sig_index, subsig_index } => {
                match self.logical.get(sig_index as usize).and_then(|sig| sig.subsignatures.get(subsig_index as usize)) {
                    Some(crate::logical::Subsignature::Body { patterns, .. }) => patterns,
                    _ => return false,
                }
            }
        };
        if atom.is_empty() {
            return false;
        }
        patterns.iter().filter_map(|p| p.pure_literal()).any(|literal| {
            literal.windows(atom.len()).enumerate().any(|(off, window)| {
                window == atom
                    && start
                        .checked_sub(off)
                        .and_then(|from| self.hay.get(from..from.checked_add(literal.len())?))
                        == Some(literal)
            })
        })
    }

    /// Try to verify a pattern at the given position. Returns true if ANY
    /// pattern of this slot matches. Once a slot is verified, we don't
    /// re-verify it.
    fn try_verify(&self, slot_id: SlotId, start: usize, already: bool) -> bool {
        if already {
            return true;
        }
        let Some(slot) = self.slots.get(slot_id as usize) else { return false };
        let crate::atomfilter::SlotTarget::LogicalSubsig { sig_index, subsig_index } = slot.target else { return false };
        let Some(sig) = self.logical.get(sig_index as usize) else { return false };
        let Some(crate::logical::Subsignature::Body { patterns, .. }) = sig.subsignatures.get(subsig_index as usize) else {
            return false;
        };
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
            verify: Vec::new(),
            touched: Vec::new(),
            vr_target: None,
            full_reset: true,
        }
    }

    /// Counts of the last scan.
    pub fn counts(&self) -> SlotCounts<'_> {
        SlotCounts { counts: &self.counts, saturated: &self.saturated }
    }

    /// Every slot whose count the last scan changed (may repeat), or None before
    /// the first scan.
    pub fn touched(&self) -> Option<&[u32]> {
        (!self.full_reset).then_some(&self.touched[..])
    }

    /// Inline verification results of the last `scan_with_verify`.
    pub(crate) fn verify_results(&self) -> &[bool] {
        &self.verify
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
        pma: &DoubleArrayAhoCorasick<u32>,
        exact: bool,
        atom_to_slots: &[Box<[SlotId]>],
        slot_to_values: &[Box<[u32]>],
        slots: &[SlotDef],
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        hay: &[u8],
        file_type_target: u32,
        counts: &mut [u32],
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
        touched: &mut Vec<u32>,
    ) {
        for m in pma.find_overlapping_iter(hay) {
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
                    let literal = verify_ctx.is_some_and(|v| v.is_literal(st));
                    if literal && !exact {
                        if counts[st] == 0 {
                            touched.push(slot_id);
                        }
                        saturated[st >> 6] |= 1 << (st & 63);
                    }
                    let keep_verifying = literal
                        && exact
                        && counts[st] < LITERAL_HIT_LIMIT
                        && verify_results.get(st) == Some(&false);
                    if counts[st] >= slots[st].threshold && !keep_verifying {
                        saturated[st >> 6] |= 1 << (st & 63);
                        touched.push(slot_id);
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
                    if counts[st] == 0 {
                        touched.push(slot_id);
                    }
                    counts[st] = counts[st].saturating_add(1);
                    out_stats.incremented += 1;
                    // Inline verification: if the atom matched at `start`,
                    // try to verify the full pattern immediately (like
                    // ClamAV's ac_findmatch). Once verified, the slot
                    // won't need a separate count_all rescan.
                    // `abs_start = data_offset + start` is the position
                    // within the original full data buffer.
                    if let Some(vctx) = verify_ctx {
                        if st < verify_results.len() && !verify_results[st] {
                            let verified = if literal && exact {
                                vctx.verify_literal(slot_id, data_offset + start, &hay[start..m.end()])
                            } else {
                                vctx.try_verify(slot_id, data_offset + start, false)
                            };
                            if verified {
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
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
        touched: &mut Vec<u32>,
    ) {
        let pma = Self::resolve_scanner(pt, exact);
        let pma = match pma {
            Some(p) => p,
            _ => return,
        };
        let t0 = std::time::Instant::now();
        Self::run_dense_chunk(
            pma,
            exact,
            &pt.atom_to_slots,
            &pt.slot_to_values,
            slots,
            saturated,
            value_remaining,
            hay,
            file_type_target,
            counts,
            out_stats,
            verify_ctx,
            verify_results,
            data_offset,
            touched,
        );
        out_stats.daachorse_us = t0.elapsed().as_micros() as u64;
    }

    /// Resolve the scanner for a target (exact or nocase).
    fn resolve_scanner<'b>(pt: &'b PerTarget, exact: bool) -> Option<&'b DoubleArrayAhoCorasick<u32>> {
        if exact {
            pt.exact.as_ref()
        } else {
            pt.nocase.as_ref()
        }
    }

    /// Run the daachorse DFA on `hay` in parallel chunks. Each chunk has a small
    /// overlap so patterns that cross cut points are still detected.
    ///
    /// `data_offset`: the offset of `hay[0]` within the full data buffer.
    #[allow(clippy::too_many_arguments)]
    fn run_dense_parallel(
        db: &AtomFilterDb,
        pt: &PerTarget,
        exact: bool,
        n_threads: usize,
        hay: &[u8],
        file_type_target: u32,
        saturated: &mut [u64],
        value_remaining: &mut [u32],
        counts: &mut [u32],
        out_stats: &mut AutomatonStats,
        verify_ctx: Option<&InlineVerifyCtx>,
        verify_results: &mut [bool],
        data_offset: usize,
        touched: &mut Vec<u32>,
    ) {
        let Some(pma) = Self::resolve_scanner(pt, exact) else {
            return;
        };
        const OVERLAP: usize = 1024;

        let t0 = std::time::Instant::now();
        let chunk_size = hay.len().div_ceil(n_threads);
        let n_chunks = hay.len().div_ceil(chunk_size);
        let chunk_at = |tid: usize| {
            let start = tid * chunk_size;
            (start, (start + chunk_size + OVERLAP).min(hay.len()))
        };
        let has_verify = verify_ctx.is_some();
        let mut workers = take_sweep_workers(n_chunks - 1);
        let mut stats: Vec<AutomatonStats> = (0..n_chunks).map(|_| AutomatonStats::default()).collect();
        let (first_stats, worker_stats) = stats.split_first_mut().expect("at least one chunk");

        std::thread::scope(|s| {
            for (i, (worker, st)) in workers.iter_mut().zip(worker_stats.iter_mut()).enumerate() {
                let (start, end) = chunk_at(i + 1);
                let chunk = &hay[start..end];
                s.spawn(move || {
                    worker.prepare(db, pt);
                    let AtomScratch { saturated, value_remaining, counts, verify, touched, .. } = worker;
                    let verify: &mut [bool] = if has_verify { verify } else { &mut [] };
                    Self::run_dense_chunk(
                        pma,
                        exact,
                        &pt.atom_to_slots,
                        &pt.slot_to_values,
                        &db.slots,
                        saturated,
                        value_remaining,
                        chunk,
                        file_type_target,
                        counts,
                        st,
                        verify_ctx,
                        verify,
                        data_offset + start,
                        touched,
                    );
                });
            }
            let (start, end) = chunk_at(0);
            Self::run_dense_chunk(
                pma,
                exact,
                &pt.atom_to_slots,
                &pt.slot_to_values,
                &db.slots,
                saturated,
                value_remaining,
                &hay[start..end],
                file_type_target,
                counts,
                first_stats,
                verify_ctx,
                verify_results,
                data_offset + start,
                touched,
            );
        });

        for st in &stats {
            out_stats.daachorse_matches += st.daachorse_matches;
            out_stats.inner_iterations += st.inner_iterations;
            out_stats.saturated_skip += st.saturated_skip;
            out_stats.ft_skip += st.ft_skip;
            out_stats.saturated_count += st.saturated_count;
            out_stats.saturated_dec += st.saturated_dec;
            out_stats.incremented += st.incremented;
        }
        for worker in &mut workers {
            for &slot_id in &worker.touched {
                let st = slot_id as usize;
                let added = std::mem::take(&mut worker.counts[st]);
                if added > 0 {
                    if counts[st] == 0 {
                        touched.push(slot_id);
                    }
                    counts[st] = counts[st].saturating_add(added);
                    if (worker.saturated[st >> 6] >> (st & 63)) & 1 == 1 {
                        saturated[st >> 6] |= 1 << (st & 63);
                    }
                }
                if has_verify && worker.verify[st] {
                    verify_results[st] = true;
                }
            }
        }
        return_sweep_workers(workers);
        out_stats.daachorse_us = t0.elapsed().as_micros() as u64;
    }

    fn prepare(&mut self, db: &AtomFilterDb, pt: &PerTarget) {
        let n_slots = db.slots.len();
        let sat_words = (n_slots + 63) / 64;
        let sized = self.counts.len() == n_slots
            && self.verify.len() == n_slots
            && self.saturated.len() == sat_words;
        if !sized || self.full_reset {
            self.counts.clear();
            self.counts.resize(n_slots, 0);
            self.verify.clear();
            self.verify.resize(n_slots, false);
            self.saturated.clear();
            self.saturated.resize(sat_words, 0);
            self.vr_target = None;
            self.full_reset = false;
        } else {
            let same_target = self.vr_target == Some(pt.target);
            for &slot_id in &self.touched {
                let st = slot_id as usize;
                if same_target && (self.saturated[st >> 6] >> (st & 63)) & 1 == 1 {
                    for &v in pt.slot_to_values.get(st).map_or(&[][..], |b| &b[..]) {
                        let v = v as usize;
                        if let (Some(slot), Some(atoms)) = (self.value_remaining.get_mut(v), pt.atom_to_slots.get(v)) {
                            *slot = atoms.len() as u32;
                        }
                    }
                }
                self.counts[st] = 0;
                self.verify[st] = false;
                self.saturated[st >> 6] &= !(1u64 << (st & 63));
            }
            if !same_target {
                self.vr_target = None;
            }
        }
        self.touched.clear();
        if self.vr_target != Some(pt.target) || self.value_remaining.len() != pt.atom_to_slots.len() {
            self.value_remaining.clear();
            for slots in pt.atom_to_slots.iter() {
                self.value_remaining.push(slots.len() as u32);
            }
            self.vr_target = Some(pt.target);
        }
    }

    fn scan_impl<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
        verify_ctx: Option<&InlineVerifyCtx>,
    ) -> SlotCounts<'_> {
        let pt = Self::select_target(&db.per_target, file_type_target);
        self.prepare(db, pt);
        let mut touched = std::mem::take(&mut self.touched);
        let mut verify = std::mem::take(&mut self.verify);
        let verify_results: &mut [bool] = if verify_ctx.is_some() { &mut verify } else { &mut [] };

        let mut exact_stats = AutomatonStats::default();
        let mut nocase_stats = AutomatonStats::default();

        // ── Exact automaton pass over the FULL buffer ───────────────────
        // No outer Shift-OR windowing: upstream daachorse 5's
        // DoubleArrayAhoCorasick already carries its own built-in 2-gram
        // match-candidate prefilter (enabled by default) and skips dead
        // regions internally. An extra outer window would add nothing.
        if pt.exact.is_some() && !data.is_empty() {
            let n_threads = worker_count();
            if n_threads > 1 && data.len() >= 256 * 1024 {
                Self::run_dense_parallel(
                    db,
                    pt,
                    true,
                    n_threads,
                    data,
                    file_type_target,
                    &mut self.saturated,
                    &mut self.value_remaining,
                    &mut self.counts,
                    &mut exact_stats,
                    verify_ctx,
                    verify_results,
                    0,
                    &mut touched,
                );
            } else {
                Self::run_dense_automaton(
                    pt,
                    true,
                    &db.slots,
                    &mut self.saturated,
                    &mut self.value_remaining,
                    data,
                    file_type_target,
                    &mut self.counts,
                    &mut exact_stats,
                    verify_ctx,
                    verify_results,
                    0,
                    &mut touched,
                );
            }
        }

        // ── Nocase automaton pass (data_offset = 0) ──────────────────
        // Nocase atoms serve text-oriented signatures; on confidently
        // binary-typed buffers (PE/ELF/Mach-O/Java/DEX/APK/ZIP) that aren't even
        // text-like, the whole lowercased-buffer build + second DFA pass
        // costs up to seconds while promoting ~nothing (binary formats have
        // no case-folded literals worth indexing). Skipping it there is pure
        // win; every other type (incl. unknown) keeps the pass, so recall is
        // unchanged wherever case-insensitive matching could matter.
        let binary_typed = matches!(file_type_target, 1 | 6 | 9 | 12 | 16 | 17 | 18);
        if pt.nocase.is_some() && (!binary_typed || crate::scanner::is_text_like(data)) {
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
                    db,
                    pt,
                    false,
                    n_threads,
                    &lowered[..data.len()],
                    file_type_target,
                    &mut self.saturated,
                    &mut self.value_remaining,
                    &mut self.counts,
                    &mut nocase_stats,
                    verify_ctx,
                    verify_results,
                    0,
                    &mut touched,
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
                    &mut nocase_stats,
                    verify_ctx,
                    verify_results,
                    0,
                    &mut touched,
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
                "[ATOMSCAN] {} {}KB {} {}",
                target_label,
                data.len() / 1024,
                exact_info,
                nocase_info,
            );
        }

        self.touched = touched;
        self.verify = verify;
        SlotCounts { counts: &self.counts, saturated: &self.saturated }
    }

    /// Run the atom sweep only (no inline verification).
    /// For inline verification, use [`scan_with_verify`].
    pub fn scan<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
    ) -> SlotCounts<'_> {
        self.scan_impl(db, data, file_type_target, None)
    }

    /// Run the atom sweep with inline pattern verification.
    ///
    /// When an atom matches, the patterns associated with its slot are
    /// immediately verified at the match position (like ClamAV's
    /// `ac_findmatch`). Slots whose pattern is verified are set to `true`
    /// in [`Self::verify_results`], which the caller can use to skip the separate
    /// `count_all` re-scan.
    pub(crate) fn scan_with_verify<'d>(
        &mut self,
        db: &'d AtomFilterDb,
        data: &[u8],
        file_type_target: u32,
        verify_ctx: &InlineVerifyCtx,
    ) -> SlotCounts<'_> {
        self.scan_impl(db, data, file_type_target, Some(verify_ctx))
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
