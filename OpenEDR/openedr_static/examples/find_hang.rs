//! Runs the v2 extractor over a file list in parallel and reports any file that takes
//! longer than the given seconds (the one a feature dump hangs on). Emulator only.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
fn main() {
    let mut args = std::env::args().skip(1);
    let list = args.next().unwrap();
    let limit_s: u64 = args.next().unwrap_or("60".into()).parse().unwrap();
    let files: Vec<String> = std::fs::read_to_string(&list).unwrap().lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
    let n = files.len();
    let files = Arc::new(files);
    let next = Arc::new(Mutex::new(0usize));
    let running: Arc<Mutex<std::collections::HashMap<usize, Instant>>> = Default::default();
    let reported: Arc<Mutex<std::collections::HashSet<usize>>> = Default::default();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (files, next, running) = (files.clone(), next.clone(), running.clone());
        hs.push(std::thread::Builder::new().stack_size(64 << 20).spawn(move || loop {
            let i = { let mut g = next.lock().unwrap(); let i = *g; *g += 1; i };
            if i >= files.len() { break; }
            running.lock().unwrap().insert(i, Instant::now());
            if let Ok(data) = std::fs::read(&files[i]) {
                let _ = std::panic::catch_unwind(|| openedr_static::ml::pe_combined::extract_pe_features_v2(&data));
                openedr_static::ml::pe_combined::forget_emulation();
            }
            running.lock().unwrap().remove(&i);
        }).unwrap());
    }
    let t0 = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let done = (*next.lock().unwrap()).min(n);
        let r = running.lock().unwrap().clone();
        for (i, s) in &r {
            if s.elapsed() > Duration::from_secs(limit_s) && reported.lock().unwrap().insert(*i) {
                println!("SLOW >{limit_s}s: line {i}: {}", files[*i]);
            }
        }
        if r.is_empty() && done >= n { break; }
        if t0.elapsed().as_secs() % 60 < 5 { eprintln!("{done}/{n} started, {} running", r.len()); }
        if r.len() > 0 && r.values().all(|s| s.elapsed() > Duration::from_secs(limit_s * 5)) && done >= n {
            println!("only stuck files left; stopping");
            std::process::exit(0);
        }
    }
    for h in hs { let _ = h.join(); }
    println!("all {n} files done in {:.0} s", t0.elapsed().as_secs_f64());
}
