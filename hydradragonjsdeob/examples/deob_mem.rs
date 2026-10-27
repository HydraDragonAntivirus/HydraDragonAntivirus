//! Peak heap of `deobfuscate` per file, for finding the scripts that make it use a lot
//! of memory. `deob_mem <list> [max_files]`: a list of paths, one per line; prints the
//! files with the largest peak (bytes allocated above the level before the call).
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Peak;
static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = NOW.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(n, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        NOW.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Peak = Peak;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let max: usize = a.get(2).and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let list = std::fs::read_to_string(&a[1]).expect("list");
    std::panic::set_hook(Box::new(|_| {}));
    let mut rows = Vec::new();
    for p in list.lines().map(str::trim).filter(|l| !l.is_empty()).take(max) {
        let Ok(src) = std::fs::read_to_string(p) else { continue };
        if src.len() > 1 << 20 {
            continue;
        }
        let base = NOW.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let t = std::time::Instant::now();
        let r = std::panic::catch_unwind(|| hydradragonjsdeob::engine::api::JSDeobfuscator::new().max_iterations(20).deobfuscate(&src));
        let peak = PEAK.load(Ordering::Relaxed) - base;
        let (iters, mods) = match &r {
            Ok(Ok(r)) => (r.iterations, r.modifications),
            _ => (0, 0),
        };
        rows.push((peak, src.len(), iters, mods, t.elapsed().as_millis(), p.to_string()));
    }
    rows.sort_by(|x, y| y.0.cmp(&x.0));
    let total: usize = rows.iter().map(|r| r.0).sum();
    eprintln!("{} files, mean peak {} KB", rows.len(), total / rows.len().max(1) / 1024);
    println!("peak_MB\tsrc_KB\tratio\titers\tmods\tms\tpath");
    for (peak, len, it, m, ms, p) in rows.iter().take(25) {
        println!("{:.1}\t{}\t{}\t{}\t{}\t{}\t{}", *peak as f64 / 1048576.0, len / 1024, peak / (*len).max(1), it, m, ms, p);
    }
}
