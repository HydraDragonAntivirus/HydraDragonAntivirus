//! One CPU budget for the whole process, shared by every place that starts helper
//! threads for one scan (the atom sweep and signature verification here, the
//! engine's object scans, the server's static report).
//!
//! Each of those used to size itself from the core count alone: a server with N
//! engine workers, each scan fanning out to up to 8 object threads, each of those
//! starting 4 sweep threads, had several times more runnable threads than cores.
//! The surplus only waits for a core (and evicts the others' caches): the stage
//! timer shows it as wall time without CPU. Here a thread that does scan work holds
//! a slot (`worker`), and helpers are handed out only while slots are free
//! (`helpers`): with every core busy a scan runs its work inline, on an idle machine
//! it still fans out.
//!
//! Helper CPU time is added to the thread that started them (`offloaded_cpu_ns`),
//! so a stage that hands its work to helpers does not look like it was waiting.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Slots in total (0: not set yet, the core count).
static LIMIT: AtomicUsize = AtomicUsize::new(0);
/// Slots in use: registered workers plus granted helpers.
static BUSY: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// CPU time of the helpers this thread started, since the thread began.
    static OFFLOADED_CPU_NS: Cell<u64> = const { Cell::new(0) };
}

/// Logical processors, read once (see `atomscan::core_count` for why).
pub fn cores() -> usize {
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(1);
    CACHED.store(n, Ordering::Relaxed);
    n
}

/// Sets the number of threads that may do scan work at once (0: the core count).
pub fn set_limit(n: usize) {
    LIMIT.store(n, Ordering::Relaxed);
}

/// Threads that may do scan work at once.
pub fn limit() -> usize {
    match LIMIT.load(Ordering::Relaxed) {
        0 => cores(),
        n => n,
    }
}

/// Slots in use now (workers and helpers).
pub fn busy() -> usize {
    BUSY.load(Ordering::Relaxed)
}

/// A thread doing scan work (an engine worker running a job). Always granted: the
/// workers are sized by their own setting; they only make helpers scarcer.
pub struct Worker(());

pub fn worker() -> Worker {
    BUSY.fetch_add(1, Ordering::Relaxed);
    Worker(())
}

impl Drop for Worker {
    fn drop(&mut self) {
        BUSY.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Helper threads granted to one parallel section, given back on drop. `count` may
/// be 0: the caller then does the work itself.
pub struct Helpers {
    n: usize,
    cpu_ns: AtomicU64,
}

/// Up to `want` helper threads, as many as there are free slots.
pub fn helpers(want: usize) -> Helpers {
    let limit = limit();
    let mut cur = BUSY.load(Ordering::Relaxed);
    loop {
        let n = want.min(limit.saturating_sub(cur));
        if n == 0 {
            return Helpers { n: 0, cpu_ns: AtomicU64::new(0) };
        }
        match BUSY.compare_exchange_weak(cur, cur + n, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Helpers { n, cpu_ns: AtomicU64::new(0) },
            Err(now) => cur = now,
        }
    }
}

impl Helpers {
    pub fn count(&self) -> usize {
        self.n
    }

    /// Runs `f` on a helper thread, counting its CPU time for the thread that asked
    /// for the helpers.
    pub fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        let start = thread_cpu_ns();
        let v = f();
        self.cpu_ns.fetch_add(thread_cpu_ns().saturating_sub(start), Ordering::Relaxed);
        v
    }
}

impl Drop for Helpers {
    fn drop(&mut self) {
        if self.n > 0 {
            BUSY.fetch_sub(self.n, Ordering::Relaxed);
        }
        let cpu = *self.cpu_ns.get_mut();
        if cpu > 0 {
            let _ = OFFLOADED_CPU_NS.try_with(|c| c.set(c.get().saturating_add(cpu)));
        }
    }
}

/// CPU time of the helpers this thread started (only grows).
pub fn offloaded_cpu_ns() -> u64 {
    OFFLOADED_CPU_NS.try_with(|c| c.get()).unwrap_or(0)
}

/// CPU time (kernel + user) of the calling thread; 0 where it cannot be read.
#[cfg(windows)]
pub fn thread_cpu_ns() -> u64 {
    // FILETIME is two u32 halves, little-endian: the same bytes as a u64.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThread() -> isize;
        fn GetThreadTimes(thread: isize, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    }
    let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: the pseudo handle of the current thread and four valid out pointers.
    if unsafe { GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u) } != 0 {
        k.saturating_add(u).saturating_mul(100)
    } else {
        0
    }
}

#[cfg(not(windows))]
pub fn thread_cpu_ns() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_wanted_nothing_granted() {
        let h = helpers(0);
        assert_eq!(h.count(), 0);
        assert!(limit() >= 1);
    }

    #[test]
    fn helper_cpu_goes_to_the_owner() {
        let h = helpers(1);
        let before = offloaded_cpu_ns();
        std::thread::scope(|s| {
            s.spawn(|| h.run(|| (0..3_000_000u64).fold(0u64, |a, x| a.wrapping_add(x * x))));
        });
        drop(h);
        if cfg!(windows) {
            assert!(offloaded_cpu_ns() >= before);
        }
    }
}
