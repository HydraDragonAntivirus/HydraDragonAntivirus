//! Heap use per component: what each part of the engine keeps after loading, and how
//! high each scan stage goes while it runs. Also the time each stage takes (`stage`,
//! `time_scan`; see the notes at `StageTime`).
//!
//! Counting needs `TrackingAlloc` as the program's global allocator (multron_server
//! sets it); without it every number stays 0 and `installed()` is false. Counters are
//! per thread and cost no lock: a `measure` scope sees the allocations of its own
//! thread only, not of worker threads it starts.
//!
//! * retained - bytes allocated in the scope and not freed by it (for a loader: the
//!   size of what it built);
//! * peak - highest point above the start while the scope ran (the spike it caused);
//! * live - bytes held right now by scopes of that name still running on any thread,
//!   so a memory spike can be pinned on the stage that is in the middle of it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct TrackingAlloc;

const NO_LABEL: usize = usize::MAX;
const MAX_LABELS: usize = 64;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static LIVE: [AtomicI64; MAX_LABELS] = [const { AtomicI64::new(0) }; MAX_LABELS];

thread_local! {
    static NET: Cell<i64> = const { Cell::new(0) };
    /// Bytes kept by `Kind::Load` scopes that ran inside other scopes: left out of the
    /// enclosing scopes' numbers (a lazy one-time load is not a spike of the scan that
    /// happened to trigger it).
    static SKIP: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
    static LABEL: Cell<usize> = const { Cell::new(NO_LABEL) };
}

/// This thread's counted bytes (net of nested loads).
fn level() -> i64 {
    NET.with(Cell::get) - SKIP.with(Cell::get)
}

#[inline]
fn note(delta: i64) {
    let _ = NET.try_with(|n| {
        let v = n.get() + delta;
        n.set(v);
        let v = v - SKIP.try_with(Cell::get).unwrap_or(0);
        if delta > 0 {
            let _ = PEAK.try_with(|p| {
                if v > p.get() {
                    p.set(v)
                }
            });
        }
    });
    let _ = LABEL.try_with(|l| {
        if let Some(c) = LIVE.get(l.get()) {
            c.fetch_add(delta, Relaxed);
        }
    });
}

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            if !INSTALLED.load(Relaxed) {
                INSTALLED.store(true, Relaxed);
            }
            note(layout.size() as i64);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            note(layout.size() as i64);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        note(-(layout.size() as i64));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            note(new_size as i64 - layout.size() as i64);
        }
        p
    }
}

/// `TrackingAlloc` is the global allocator (numbers are real, not zeros).
pub fn installed() -> bool {
    INSTALLED.load(Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Built once and kept (rule sets, models, lists).
    Load,
    /// Runs per file (scan stages).
    Scan,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentMem {
    pub name: &'static str,
    pub kind: Kind,
    pub calls: u64,
    /// Load: bytes the last load kept. Scan: bytes the last call left behind.
    pub retained_bytes: i64,
    pub last_peak_bytes: i64,
    pub max_peak_bytes: i64,
    /// Input size of the call that reached `max_peak_bytes` (0 when not known).
    pub max_peak_input_bytes: u64,
    /// Held now by calls still running.
    pub live_bytes: i64,
}

static STATS: Mutex<Vec<ComponentMem>> = Mutex::new(Vec::new());

fn slot(name: &'static str, kind: Kind) -> usize {
    let mut s = STATS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = s.iter().position(|c| c.name == name) {
        return i;
    }
    s.push(ComponentMem {
        name,
        kind,
        calls: 0,
        retained_bytes: 0,
        last_peak_bytes: 0,
        max_peak_bytes: 0,
        max_peak_input_bytes: 0,
        live_bytes: 0,
    });
    s.len() - 1
}

/// Runs `f` and counts its heap use under `name` (see the module notes), and its time
/// (see [`stage`]). `input_len` is the size of what it works on (0 for loaders).
pub fn measure<T>(name: &'static str, kind: Kind, input_len: usize, f: impl FnOnce() -> T) -> T {
    // A load (engine data, the server's telemetry at start) is not a scan stage: timed
    // as one, a 70 s start-up load showed in the engine-time card as one "call" of the
    // scan stage with the same name. A lazy load during a scan stays in the time of
    // the stage that waited for it.
    let _time = (kind != Kind::Load).then(|| stage(name));
    if !installed() {
        return f();
    }
    let idx = slot(name, kind);
    let start = level();
    let outer_peak = PEAK.with(|p| p.replace(start));
    let outer_label = LABEL.with(|l| l.replace(idx));
    let v = f();
    let end = level();
    let peak = PEAK.with(Cell::get);
    LABEL.with(|l| l.set(outer_label));
    let net = end - start;
    if let Some(c) = LIVE.get(idx) {
        c.fetch_sub(net, Relaxed);
    }
    if kind == Kind::Load && outer_label != NO_LABEL {
        // Hidden from the enclosing scope: as if it had not run there.
        SKIP.with(|s| s.set(s.get() + net));
        PEAK.with(|p| p.set(outer_peak.max(start)));
    } else {
        PEAK.with(|p| p.set(outer_peak.max(peak)));
        // What this scope still holds now belongs to the enclosing one (it gives it
        // back when it ends, as part of its own net).
        if let Some(c) = LIVE.get(outer_label) {
            c.fetch_add(net, Relaxed);
        }
    }
    let rise = (peak - start).max(0);
    let mut s = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let c = &mut s[idx];
    c.calls += 1;
    c.retained_bytes = net;
    c.last_peak_bytes = rise;
    if rise >= c.max_peak_bytes {
        c.max_peak_bytes = rise;
        c.max_peak_input_bytes = input_len as u64;
    }
    v
}

/// Every component seen so far, largest first (live, then retained, then max peak).
pub fn snapshot() -> Vec<ComponentMem> {
    let mut out = STATS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for (i, c) in out.iter_mut().enumerate() {
        c.live_bytes = LIVE.get(i).map_or(0, |l| l.load(Relaxed).max(0));
    }
    out.sort_by_key(|c| std::cmp::Reverse((c.live_bytes, c.retained_bytes.max(0), c.max_peak_bytes)));
    out
}

// ---------------------------------------------------------------------------------
// Time per stage: which engine a slow scan spent its seconds in. Unlike the heap
// counters this needs no allocator and is always on (two clock reads per stage).
//
// A stage's time is its own time: stages that ran inside it on the same thread are
// left out of it (an archive member's YARA time is YARA's, not the archive's), so the
// stages of one scan add up to the scan instead of counting nested work twice. Work a
// scan hands to worker threads is counted where `in_scan_context` carries it.

thread_local! {
    /// Time of the stages that ran inside the current one on this thread.
    static INNER_NS: Cell<u64> = const { Cell::new(0) };
    /// The scan this thread works for (`time_scan`, `in_scan_context`).
    static SCAN: std::cell::RefCell<Option<Arc<ScanTimes>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StageTime {
    pub name: &'static str,
    pub calls: u64,
    /// Own time of all calls (nested stages left out).
    pub self_ns: u64,
    /// Longest own time of one call.
    pub max_ns: u64,
}

static TIMES: Mutex<Vec<StageTime>> = Mutex::new(Vec::new());

/// The stage times of one scan, from every thread that worked on it.
#[derive(Default)]
pub struct ScanTimes {
    stages: Mutex<Vec<StageTime>>,
}

fn add_time(list: &Mutex<Vec<StageTime>>, name: &'static str, ns: u64) {
    let mut l = list.lock().unwrap_or_else(|e| e.into_inner());
    match l.iter_mut().find(|s| s.name == name) {
        Some(s) => {
            s.calls += 1;
            s.self_ns += ns;
            s.max_ns = s.max_ns.max(ns);
        }
        None => l.push(StageTime { name, calls: 1, self_ns: ns, max_ns: ns }),
    }
}

/// Times the scope it lives in (until it is dropped) under `name`.
pub struct StageTimer {
    name: &'static str,
    start: Instant,
    outer_inner: u64,
}

/// Starts timing a stage: `let _t = memtrack::stage("scan:clamav");`. For stages that
/// are not a closure (blocks with early returns); `measure` times its closure itself.
pub fn stage(name: &'static str) -> StageTimer {
    StageTimer { name, start: Instant::now(), outer_inner: INNER_NS.try_with(|c| c.replace(0)).unwrap_or(0) }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        let total = self.start.elapsed().as_nanos() as u64;
        let inner = INNER_NS.try_with(|c| c.replace(self.outer_inner + total)).unwrap_or(0);
        let own = total.saturating_sub(inner);
        add_time(&TIMES, self.name, own);
        let _ = SCAN.try_with(|s| {
            if let Some(t) = s.borrow().as_ref() {
                add_time(&t.stages, self.name, own);
            }
        });
    }
}

/// Puts the previous scan context back, also when the scan panics (threads are reused).
struct ScanGuard(Option<Option<Arc<ScanTimes>>>);

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            let _ = SCAN.try_with(|s| *s.borrow_mut() = prev);
        }
    }
}

/// Runs a scan and returns, next to its result, the time each stage took in it,
/// slowest first.
pub fn time_scan<T>(f: impl FnOnce() -> T) -> (T, Vec<StageTime>) {
    let times = Arc::new(ScanTimes::default());
    let v = in_scan_context(Some(Arc::clone(&times)), f);
    let mut stages = std::mem::take(&mut *times.stages.lock().unwrap_or_else(|e| e.into_inner()));
    stages.sort_by_key(|s| std::cmp::Reverse(s.self_ns));
    (v, stages)
}

/// The scan this thread works for, to hand to worker threads it starts.
pub fn scan_context() -> Option<Arc<ScanTimes>> {
    SCAN.try_with(|s| s.borrow().clone()).ok().flatten()
}

/// Runs `f` (on a worker thread) as part of the scan `ctx` came from.
pub fn in_scan_context<T>(ctx: Option<Arc<ScanTimes>>, f: impl FnOnce() -> T) -> T {
    let _guard = ScanGuard(SCAN.try_with(|s| s.replace(ctx)).ok());
    f()
}

/// Runs `f`, whose work is done by worker threads timed on their own, and leaves its
/// time out of the enclosing stage (it only waited for them).
pub fn parallel_section<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let v = f();
    let waited = start.elapsed().as_nanos() as u64;
    let _ = INNER_NS.try_with(|c| c.set(c.get() + waited));
    v
}

/// Time per stage since the start, most own time first.
pub fn time_snapshot() -> Vec<StageTime> {
    let mut out = TIMES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    out.sort_by_key(|s| std::cmp::Reverse(s.self_ns));
    out
}

/// Memory of this process from the OS: (private / commit bytes, working set bytes,
/// peak working set bytes). Zeros when it cannot be read.
pub fn process_memory() -> (u64, u64, u64) {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX};
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut c = PROCESS_MEMORY_COUNTERS_EX { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32, ..Default::default() };
        let ok = unsafe {
            GetProcessMemoryInfo(GetCurrentProcess(), &mut c as *mut _ as *mut PROCESS_MEMORY_COUNTERS, c.cb)
        };
        if ok.is_ok() {
            return (c.PrivateUsage as u64, c.WorkingSetSize as u64, c.PeakWorkingSetSize as u64);
        }
        (0, 0, 0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // /proc/self/statm: size resident shared ... in pages.
        let page = 4096u64;
        let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
        let mut it = s.split_whitespace().map(|v| v.parse::<u64>().unwrap_or(0));
        let (size, rss) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
        (size * page, rss * page, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_without_allocator_is_transparent() {
        // Tests run with the system allocator: no counting, value passes through.
        assert_eq!(measure("t", Kind::Scan, 3, || 41 + 1), 42);
    }

    #[test]
    fn stage_times_leave_nested_stages_out() {
        let spin = |ms: u64| {
            let t = Instant::now();
            while t.elapsed().as_millis() < ms as u128 {}
        };
        let ((), stages) = time_scan(|| {
            let _outer = stage("t:outer");
            spin(20);
            measure("t:inner", Kind::Scan, 0, || spin(30));
            let ctx = scan_context();
            parallel_section(|| {
                std::thread::scope(|s| {
                    s.spawn(|| in_scan_context(ctx, || measure("t:worker", Kind::Scan, 0, || spin(30))));
                });
            });
        });
        let ms = |n: &str| stages.iter().find(|s| s.name == n).map(|s| s.self_ns / 1_000_000).unwrap();
        assert!((20..40).contains(&ms("t:outer")), "outer own time {}", ms("t:outer"));
        assert!(ms("t:inner") >= 30);
        assert!(ms("t:worker") >= 30, "worker time is part of the scan");
        assert!(stages.windows(2).all(|w| w[0].self_ns >= w[1].self_ns), "slowest first");
        assert!(scan_context().is_none(), "context put back after the scan");
    }

    #[test]
    fn note_tracks_net_peak_and_live() {
        let idx = slot("unit", Kind::Scan);
        let start = NET.with(Cell::get);
        PEAK.with(|p| p.set(start));
        let prev = LABEL.with(|l| l.replace(idx));
        note(1000);
        note(-400);
        note(100);
        LABEL.with(|l| l.set(prev));
        assert_eq!(NET.with(Cell::get) - start, 700);
        assert_eq!(PEAK.with(Cell::get) - start, 1000);
        assert_eq!(LIVE[idx].load(Relaxed), 700);
        LIVE[idx].store(0, Relaxed);
        NET.with(|n| n.set(start));
    }
}
