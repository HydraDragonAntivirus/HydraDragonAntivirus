//! Heap use per component: what each part of the engine keeps after loading, and how
//! high each scan stage goes while it runs.
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
use std::sync::Mutex;

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

/// Runs `f` and counts its heap use under `name` (see the module notes).
/// `input_len` is the size of what it works on (0 for loaders).
pub fn measure<T>(name: &'static str, kind: Kind, input_len: usize, f: impl FnOnce() -> T) -> T {
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
