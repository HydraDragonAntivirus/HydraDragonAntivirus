//! pe_feature_dump — PE ML features with the engine's own extractor.
//!
//!   pe_feature_dump @<files.lst> <out.csv>          v1: 65 shell features
//!   pe_feature_dump --v2 @<files.lst> <out.csv>     v2: shell + inner + combined
//!   pe_feature_dump --show <file>                   one file's v2 vector, by name
//!
//! `files.lst` is a UTF-8 list of files, one path per line (train_pe_lgbm.py writes one
//! per feature chunk). Calls openedr_static's `extract_pe_features` (v1) or
//! `extract_pe_features_v2` (v2: the content an archive / installer holds or a packed PE
//! unpacks to, kept apart from the shell, plus ASCII / UTF-16LE string counts over both;
//! see openedr_static/src/ml/pe_combined.rs), so the features the model learns from are
//! byte for byte what the engine computes at scan time. Files the extractor rejects
//! (not a PE) are left out.
//! Output: CSV `line,<features>` with the feature names from the engine in the header;
//! `line` is the 0-based line of the file in the list.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use openedr_static::ml::features::PeFeatureVector;
use openedr_static::ml::pe_combined::{extract_pe_features_v2, inner_of, pe_v2_feature_names, InnerSource};
use openedr_static::ml::pe_features::extract_pe_features;
use rayon::prelude::*;

/// Emulation and archive parsing go deep; give every worker room.
const STACK: usize = 64 * 1024 * 1024;

fn main() {
    openedr_static::ml::pe_string_ml::enable_multron_training_whitelist();
    rayon::ThreadPoolBuilder::new().stack_size(STACK).build_global().expect("thread pool");
    let worker = std::thread::Builder::new().stack_size(STACK).spawn(run).expect("work thread");
    if worker.join().is_err() {
        std::process::exit(1);
    }
}

fn usage() -> ! {
    eprintln!("usage: pe_feature_dump [--v2] @<files.lst> <out.csv>\n       pe_feature_dump --harvest-strings @<files.lst> <out.bin>\n       pe_feature_dump --show <file>");
    std::process::exit(2);
}

/// Training only: emulates / unpacks every file exactly as the scanner does and writes the
/// keys of the inner PE's non-benign strings (malicious or unknown) per file, as
/// `u32 count` + `count x u64` records. `xorfilter_writer --build-pe-malicious-from-harvest`
/// turns them into `pe_strings_malicious.xf`. Plain std threads, one emulation per worker.
fn harvest_strings(list: &str, out: &str) {
    use std::sync::Mutex;
    let text = std::fs::read_to_string(list).unwrap_or_else(|e| {
        eprintln!("cannot read file list {list}: {e}");
        std::process::exit(2);
    });
    let files: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    std::panic::set_hook(Box::new(|_| {}));
    let w = Mutex::new(std::io::BufWriter::with_capacity(
        1 << 22,
        std::fs::File::create(out).unwrap_or_else(|e| {
            eprintln!("cannot create {out}: {e}");
            std::process::exit(2);
        }),
    ));
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let with_inner = AtomicUsize::new(0);
    let strings_total = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..workers {
            std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(s, || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = files.get(i) else { break };
                    if let Ok(bytes) = std::fs::read(p) {
                        let keys = std::panic::catch_unwind(|| openedr_static::ml::pe_combined::pe_inner_harvest_keys(&bytes)).ok().flatten();
                        openedr_static::ml::pe_combined::forget_emulation();
                        if let Some(keys) = keys {
                            with_inner.fetch_add(1, Ordering::Relaxed);
                            strings_total.fetch_add(keys.len(), Ordering::Relaxed);
                            let mut g = w.lock().unwrap();
                            let _ = g.write_all(&(keys.len() as u32).to_le_bytes());
                            for k in keys {
                                let _ = g.write_all(&k.to_le_bytes());
                            }
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % 500 == 0 {
                        eprintln!(
                            "  harvest {n}/{}: {} with inner PE, {} non-benign string keys",
                            files.len(),
                            with_inner.load(Ordering::Relaxed),
                            strings_total.load(Ordering::Relaxed)
                        );
                    }
                })
                .expect("worker");
        }
    });
    let _ = w.lock().unwrap().flush();
    eprintln!(
        "harvest done: {} files, {} with an inner PE, {} non-benign string keys",
        files.len(),
        with_inner.load(Ordering::Relaxed),
        strings_total.load(Ordering::Relaxed)
    );
}

fn run() {
    let mut a: Vec<String> = std::env::args().skip(1).collect();
    if a.first().map(String::as_str) == Some("--show") {
        // RUST_LOG=debug shows the emulator's own messages (faulting addresses, ...).
        let _ = env_logger::try_init();
        let Some(path) = a.get(1) else { usage() };
        show(path);
        return;
    }
    let v2 = a.first().map(String::as_str) == Some("--v2");
    if v2 {
        a.remove(0);
    }
    if a.first().map(String::as_str) == Some("--harvest-strings") {
        a.remove(0);
        let (Some(list), Some(out)) = (a.first().and_then(|s| s.strip_prefix('@')), a.get(1)) else { usage() };
        harvest_strings(list, out);
        return;
    }
    let (Some(list), Some(out)) = (a.first().and_then(|s| s.strip_prefix('@')), a.get(1)) else { usage() };
    let text = std::fs::read_to_string(list).unwrap_or_else(|e| {
        eprintln!("cannot read file list {list}: {e}");
        std::process::exit(2);
    });
    let files: Vec<&str> = text.lines().map(str::trim).collect();
    std::panic::set_hook(Box::new(|_| {})); // malformed PE: skip the file quietly

    let done = AtomicUsize::new(0);
    let rows: Vec<(usize, Vec<f32>)> = files
        .par_iter()
        .enumerate()
        .filter(|(_, p)| !p.is_empty())
        .filter_map(|(i, p)| {
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 2000 == 0 {
                eprintln!("  {n}/{}", files.len());
            }
            let bytes = std::fs::read(p).ok()?;
            let f = if v2 {
                std::panic::catch_unwind(|| extract_pe_features_v2(&bytes)).ok()??.to_vec()
            } else {
                std::panic::catch_unwind(|| extract_pe_features(&bytes)).ok()??.to_array().to_vec()
            };
            Some((i, f))
        })
        .collect();

    let mut w = std::io::BufWriter::new(std::fs::File::create(out).unwrap_or_else(|e| {
        eprintln!("cannot create {out}: {e}");
        std::process::exit(2);
    }));
    let names: Vec<String> = if v2 { pe_v2_feature_names() } else { PeFeatureVector::NAMES.iter().map(|s| s.to_string()).collect() };
    writeln!(w, "line,{}", names.join(",")).expect("write");
    let mut rows = rows;
    rows.sort_by_key(|r| r.0);
    for (i, f) in rows {
        let vals: Vec<String> = f.iter().map(|v| format!("{v:e}")).collect();
        writeln!(w, "{i},{}", vals.join(",")).expect("write");
    }
}

/// Prints each unpacking step for one file (why an inner image is or is not there).
fn unpack_trace(bytes: &[u8]) {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    use openedr_static::ml::pe_combined::{should_unpack, UNPACK_MAX_INSTRUCTIONS};
    println!("format: {:?}; should_unpack: {}", hydradragonextractor::detect_format(bytes), should_unpack(bytes));
    let sample = match Sample::from_bytes(bytes) {
        Ok(s) => s,
        Err(e) => return println!("unpack: Sample::from_bytes failed: {e}"),
    };
    let ep = entrypoint(&sample.opt_header);
    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    if let Err(e) = eng.init_uc() {
        return println!("unpack: init_uc failed: {e}");
    }
    // Same settings as pe_combined::unpack.
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);
    let r = eng.emu_from(ep, 20_000_000, UNPACK_MAX_INSTRUCTIONS);
    let mut exec: Vec<_> = eng.sections_executed.iter().collect();
    exec.sort();
    println!("unpack: emu {:?}; sections executed {exec:?}; write ranges {}; wx {:?}; api calls {:?}", r, eng.write_targets.len(), eng.wx_hit, eng.apicall_counter);
    match eng.dump_bytes() {
        Ok(d) => println!("unpack: dump {} bytes, same as file: {}", d.len(), d == bytes),
        Err(e) => println!("unpack: dump_bytes failed: {e}"),
    }
}

/// Prints one file's v2 vector with the names, and where its inner part came from.
fn show(path: &str) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    });
    unpack_trace(&bytes);
    let inner = inner_of(&bytes);
    let source = match inner.source {
        InnerSource::None => "none",
        InnerSource::Unpacked => "unpacked by hydradragonunicorn",
        InnerSource::Extracted => "extracted by hydradragonextractor",
        InnerSource::UnpackFailed => "the emulator failed the run before it unpacked anything",
        InnerSource::Image => "not packed: its own memory image after the run",
    };
    println!(
        "inner: {source}; members {}; inner PE {}; {} bytes; strings ascii {} / utf16 {}",
        inner.members,
        if inner.pe.is_some() { "yes" } else { "no" },
        inner.bytes,
        inner.strings.ascii,
        inner.strings.utf16
    );
    let Some(v) = extract_pe_features_v2(&bytes) else {
        println!("not a PE the extractor reads");
        return;
    };
    for (n, x) in pe_v2_feature_names().iter().zip(v) {
        println!("{n} = {x}");
    }
}
