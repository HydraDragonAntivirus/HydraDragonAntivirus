//! Per-engine RAM + CPU metrics, to diagnose which engine drives process memory
//! and scan time.
//!
//! RAM cannot be attributed to an engine from the OS directly (one shared heap), so
//! engine load RAM is measured as the process working-set DELTA across that engine's
//! load. That delta is only meaningful when loads are SEQUENTIAL, so the pipeline
//! loads sequentially when metrics are enabled (`HDAV_METRICS=1` or
//! `PipelineConfig::collect_metrics`); normal startup stays parallel/fast.
//!
//! Scan CPU is the per-engine wall time already reported in `EngineResult.elapsed_ms`,
//! aggregated across all scans.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Current process working-set size (resident RAM), MiB. Windows; 0.0 elsewhere.
pub fn working_set_mb() -> f64 {
    process_mem().0
}

/// Peak process working-set size (high-water mark), MiB.
pub fn peak_working_set_mb() -> f64 {
    process_mem().1
}

/// Total process CPU time (user + kernel), seconds. Windows; 0.0 elsewhere.
pub fn process_cpu_secs() -> f64 {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct Filetime {
            low: u32,
            high: u32,
        }
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn GetProcessTimes(
                process: isize,
                creation: *mut Filetime,
                exit: *mut Filetime,
                kernel: *mut Filetime,
                user: *mut Filetime,
            ) -> i32;
        }
        let to_secs = |f: &Filetime| ((f.high as u64) << 32 | f.low as u64) as f64 / 1e7;
        unsafe {
            let (mut c, mut e, mut k, mut u) = (
                Filetime { low: 0, high: 0 },
                Filetime { low: 0, high: 0 },
                Filetime { low: 0, high: 0 },
                Filetime { low: 0, high: 0 },
            );
            if GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) != 0 {
                return to_secs(&k) + to_secs(&u);
            }
        }
    }
    0.0
}

#[cfg(windows)]
pub fn process_mem() -> (f64, f64) {
    #[repr(C)]
    struct Pmc {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        rest: [usize; 6],
    }
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, c: *mut Pmc, cb: u32) -> i32;
    }
    unsafe {
        let mut c: Pmc = std::mem::zeroed();
        c.cb = std::mem::size_of::<Pmc>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            let mb = |b: usize| b as f64 / (1024.0 * 1024.0);
            return (mb(c.working_set_size), mb(c.peak_working_set_size));
        }
    }
    (0.0, 0.0)
}

#[cfg(not(windows))]
pub fn process_mem() -> (f64, f64) {
    (0.0, 0.0)
}

/// Trim the process working set back to the OS (`EmptyWorkingSet`). After the
/// one-time engine load, the working set holds the load high-water-mark — pages
/// touched while loading but not needed while the AV idles. Trimming returns them;
/// they fault back in on demand when a scan actually touches them. This sharply
/// lowers *resident* RAM at idle (the memory stays committed, just not resident).
pub fn trim_working_set() {
    #[cfg(windows)]
    unsafe {
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32EmptyWorkingSet(process: isize) -> i32;
        }
        let _ = K32EmptyWorkingSet(GetCurrentProcess());
    }
}

/// Per-engine load metric: RAM the engine added (working-set delta) and how long it
/// took. `mem_mb` is `None` when metrics weren't collected sequentially.
#[derive(Clone, Debug)]
pub struct EngineLoad {
    pub name: &'static str,
    pub load_ms: u64,
    pub mem_mb: Option<f64>,
    pub items: usize,
}

/// Run `f` (an engine loader) measuring its load time and, if `measure_mem`, the
/// process working-set delta it caused. `items` is a count (signatures/rules) for
/// context, derived from the loaded value by `count`.
pub fn measure_load<T>(
    name: &'static str,
    measure_mem: bool,
    count: impl FnOnce(&T) -> usize,
    f: impl FnOnce() -> T,
) -> (T, EngineLoad) {
    let before = if measure_mem { working_set_mb() } else { 0.0 };
    let t0 = std::time::Instant::now();
    let val = f();
    let load_ms = t0.elapsed().as_millis() as u64;
    let mem_mb = if measure_mem {
        Some((working_set_mb() - before).max(0.0))
    } else {
        None
    };
    let items = count(&val);
    (val, EngineLoad { name, load_ms, mem_mb, items })
}

/// Running totals of per-engine SCAN cost, aggregated across all scans.
#[derive(Default)]
pub struct ScanCpu {
    inner: Mutex<BTreeMap<&'static str, (u64, u64)>>, // name -> (calls, total_ms)
}

impl ScanCpu {
    pub fn record(&self, engine: &'static str, ms: u64) {
        let mut g = self.inner.lock().unwrap();
        let e = g.entry(engine).or_insert((0, 0));
        e.0 += 1;
        e.1 += ms;
    }

    pub fn snapshot(&self) -> Vec<(&'static str, u64, u64)> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.0, v.1))
            .collect()
    }
}

/// Format a human-readable per-engine RAM + CPU report.
pub fn format_report(loads: &[EngineLoad], scan: &ScanCpu) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let (rss, peak) = process_mem();
    let cpu = process_cpu_secs();
    let _ = writeln!(
        s,
        "── HydraDragon engine metrics ──  process RSS {:.0} MB (peak {:.0} MB), CPU {:.1}s",
        rss, peak, cpu
    );
    let _ = writeln!(s, "{:<16} {:>9} {:>11} {:>10}", "engine", "load", "RAM", "items");
    let mut sum_mem = 0.0;
    for l in loads {
        let mem = l.mem_mb.map(|m| format!("{:.1} MB", m)).unwrap_or_else(|| "—".into());
        if let Some(m) = l.mem_mb {
            sum_mem += m;
        }
        let _ = writeln!(
            s,
            "{:<16} {:>7}ms {:>11} {:>10}",
            l.name, l.load_ms, mem, l.items
        );
    }
    if sum_mem > 0.0 {
        let _ = writeln!(
            s,
            "{:<16} {:>9} {:>11} (overhead/fragmentation: {:.0} MB)",
            "── total", "", format!("{:.1} MB", sum_mem), (rss - sum_mem).max(0.0)
        );
    }
    let scans = scan.snapshot();
    if !scans.is_empty() {
        let _ = writeln!(s, "scan CPU by engine:");
        for (name, calls, total_ms) in scans {
            let _ = writeln!(
                s,
                "  {:<14} {:>6} calls  {:>8}ms  ({:.2}ms/call)",
                name, calls, total_ms,
                if calls > 0 { total_ms as f64 / calls as f64 } else { 0.0 }
            );
        }
    }
    s
}
