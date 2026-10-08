//! tlsh_builder — fast TLSH tooling for HydraDragon / VIRUSKOV (fast-tlsh, multi-threaded).
//!
//! Subcommands:
//!   hash       Hash files/folders -> CSV (sha256,tlsh,size,path) or JSONL (tlsh_index.jsonl format)
//!   blacklist  Hash a malware folder (and/or MalwareBazaar full.csv) -> tlsh_blacklist.txt
//!   compare    Closest digests in a database to a file or a TLSH string
//!   refs       Hash + structural fingerprint of every PE / APK -> tlsh_whitelist_refs.jsonl
//!              (the smart-whitelist reference corpus loaded by multron_server)
//!   tune       Measure smart-whitelist risk: how close malware gets to a clean corpus,
//!              and how much of it the full server rule (distance + injection guard)
//!              would wrongly whitelist
//!
//! Output digests are the standard "T1..." form (identical to Trend Micro's reference
//! implementation, MalwareBazaar and VirusTotal).

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::{Parser, Subcommand};

// Same code as the server, so fingerprints and guard decisions are identical.
#[allow(dead_code)]
#[path = "../../OpenEDR/multron_server_rs/src/analyzer.rs"]
mod analyzer;
#[allow(dead_code)]
#[path = "../../OpenEDR/multron_server_rs/src/fingerprint.rs"]
mod fingerprint;
#[allow(dead_code)]
#[path = "../../OpenEDR/multron_server_rs/src/apk.rs"]
mod apk;

use fingerprint::{accept, ApkFp, Fingerprint, RefLine, Structure, SMART_WL_MAX_DIST, SMART_WL_MAX_DIST_EP_MOVED};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tlsh::{FuzzyHashType, Tlsh};

#[derive(Parser)]
#[command(name = "tlsh_builder", version, about = "Fast TLSH digests (fast-tlsh) for HydraDragon / VIRUSKOV")]
struct Cli {
    /// Worker threads (default: all cores)
    #[arg(short = 'j', long, global = true)]
    threads: Option<usize>,
    /// hash/refs: stop starting new files after this many seconds (for time-limited
    /// shells; combine with --resume and run again until it reports "complete")
    #[arg(long, global = true)]
    deadline: Option<u64>,
    /// hash/refs: append to the output and skip files listed in <output>.done
    #[arg(long, global = true)]
    resume: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hash every file under the given paths
    Hash {
        /// Files or folders (recursive)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Write JSON lines {"sha256","tlsh","size"} (multron_server tlsh_index.jsonl format)
        #[arg(long)]
        jsonl: bool,
        /// APKs: hash the concatenated classes*.dex instead of the whole file (what the
        /// server compares for APKs); files without DEX are skipped
        #[arg(long)]
        dex: bool,
        /// Skip files larger than this many MB
        #[arg(long, default_value_t = 100)]
        max_mb: u64,
    },
    /// Build a TLSH blacklist (one digest per line) for tlsh_signatures/tlsh_blacklist.txt
    Blacklist {
        /// Malware folders to hash (recursive)
        paths: Vec<PathBuf>,
        /// MalwareBazaar full.csv (TLSH column is read; repeatable)
        #[arg(long = "mb-csv")]
        mb_csv: Vec<PathBuf>,
        /// Existing TLSH lists to merge (one digest per line; repeatable)
        #[arg(long = "merge")]
        merge: Vec<PathBuf>,
        #[arg(short, long, default_value = "tlsh_blacklist.txt")]
        output: PathBuf,
        #[arg(long, default_value_t = 100)]
        max_mb: u64,
    },
    /// Closest digests to a file or TLSH string
    Compare {
        /// File path or a "T1..." digest
        target: String,
        /// Databases: CSV from `hash`, JSONL, or plain TLSH lists (repeatable)
        #[arg(short, long, required = true)]
        db: Vec<PathBuf>,
        #[arg(long, default_value_t = 80)]
        max_dist: u32,
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Smart-whitelist reference corpus: TLSH + structural fingerprint of every PE and APK (APK: DEX TLSH + signer/manifest)
    Refs {
        /// Files or folders (recursive) or .lst lists; only PE and APK files are written
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(short, long, default_value = "tlsh_whitelist_refs.jsonl")]
        output: PathBuf,
        #[arg(long, default_value_t = 100)]
        max_mb: u64,
    },
    /// Smart-whitelist tuning: for every malware file, distance to the closest clean file
    Tune {
        /// Clean corpus: folder(s) or `hash` CSV/JSONL databases
        #[arg(long, required = true)]
        clean: Vec<PathBuf>,
        /// Malware corpus: folder(s) or databases
        #[arg(long, required = true)]
        malware: Vec<PathBuf>,
        #[arg(long, default_value_t = 100)]
        max_mb: u64,
        /// Write the malware files that come within this distance of a clean file
        #[arg(long, default_value_t = 20)]
        report_dist: u32,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

#[derive(Clone)]
struct Rec {
    sha256: String,
    tlsh: Tlsh,
    size: u64,
    path: String,
    /// PE or APK structure (from `refs` JSONL), for the full-rule test in `tune`.
    st: Option<Structure>,
}

// ------------------------------------------------------------------ hashing

fn list_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("lst") {
            // A file list (one path per line), e.g. from `find`: avoids re-walking slow mounts.
            if let Ok(f) = File::open(p) {
                out.extend(BufReader::new(f).lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()).map(PathBuf::from));
            }
        } else if p.is_file() {
            out.push(p.clone());
        } else {
            for e in walkdir::WalkDir::new(p).follow_links(false).into_iter().flatten() {
                if e.file_type().is_file() {
                    out.push(e.into_path());
                }
            }
        }
    }
    out
}

fn hash_file(p: &Path, max_bytes: u64) -> Option<Rec> {
    hash_file_opt(p, max_bytes, false)
}

fn hash_file_opt(p: &Path, max_bytes: u64, dex: bool) -> Option<Rec> {
    let meta = std::fs::metadata(p).ok()?;
    if meta.len() < 50 || meta.len() > max_bytes {
        return None; // TLSH needs at least 50 bytes
    }
    let data = std::fs::read(p).ok()?;
    let tlsh = if dex {
        let code = apk::dex_code(&data)?; // sha256/size below stay those of the APK
        tlsh::hash_buf(&code).ok()?
    } else {
        tlsh::hash_buf(&data).ok()? // fails on too-uniform data
    };
    Some(Rec {
        sha256: hex::encode(Sha256::digest(&data)),
        tlsh,
        size: data.len() as u64,
        path: p.display().to_string(),
        st: None,
    })
}

fn hash_paths(paths: &[PathBuf], max_mb: u64) -> Vec<Rec> {
    let files = list_files(paths);
    let total = files.len();
    let done = AtomicUsize::new(0);
    let started = Instant::now();
    let max = max_mb * 1024 * 1024;
    let recs: Vec<Rec> = files
        .par_iter()
        .filter_map(|p| {
            let r = hash_file(p, max);
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 5000 == 0 || n == total {
                eprintln!("[tlsh] {n}/{total} files ({:.0}/s)", n as f64 / started.elapsed().as_secs_f64().max(0.001));
            }
            r
        })
        .collect();
    eprintln!(
        "[tlsh] {} digests from {} files in {:.1}s ({} skipped: <50 bytes, too large, unreadable or too uniform)",
        recs.len(),
        total,
        started.elapsed().as_secs_f64(),
        total - recs.len()
    );
    recs
}

// ------------------------------------------------------------------ resumable runs

struct RunOpts {
    deadline: Option<u64>,
    resume: bool,
}

/// Streams `work` over the files under `paths`, appending each produced line to
/// `output`. With `resume`, files already listed in `<output>.done` are skipped and
/// the output is appended to; with `deadline`, no new file is started after that many
/// seconds, so a large corpus can be processed by repeated time-limited runs.
fn run_resumable(
    tag: &str,
    paths: &[PathBuf],
    output: &Path,
    header: Option<&str>,
    opts: &RunOpts,
    work: impl Fn(&Path) -> Option<String> + Sync,
) {
    let done_path = PathBuf::from(format!("{}.done", output.display()));
    let mut done_set: HashSet<String> = HashSet::new();
    if opts.resume {
        if let Ok(f) = File::open(&done_path) {
            done_set.extend(BufReader::new(f).lines().map_while(Result::ok));
        }
    }
    let files: Vec<PathBuf> = list_files(paths).into_iter().filter(|p| !done_set.contains(&p.display().to_string())).collect();
    let total = files.len();
    let fresh = !opts.resume || !output.exists();
    let out = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(opts.resume)
        .truncate(!opts.resume)
        .open(output)
        .expect("cannot create output");
    let mut out = BufWriter::new(out);
    if fresh {
        if let Some(h) = header {
            writeln!(out, "{h}").unwrap();
        }
    }
    let done_w = opts.resume.then(|| {
        BufWriter::new(std::fs::OpenOptions::new().create(true).append(true).open(&done_path).expect("cannot open .done"))
    });
    let w = std::sync::Mutex::new((out, done_w));
    let done = AtomicUsize::new(0);
    let written = AtomicUsize::new(0);
    let started = Instant::now();
    let deadline = opts.deadline.map(std::time::Duration::from_secs);
    files.par_iter().for_each(|p| {
        if deadline.is_some_and(|d| started.elapsed() >= d) {
            return;
        }
        let line = work(p);
        let mut g = w.lock().unwrap();
        if let Some(l) = line {
            let _ = writeln!(g.0, "{l}");
            written.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(d) = g.1.as_mut() {
            let _ = writeln!(d, "{}", p.display());
        }
        drop(g);
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 2000 == 0 {
            eprintln!(
                "[{tag}] {n}/{total} files, {} written ({:.0} files/s)",
                written.load(Ordering::Relaxed),
                n as f64 / started.elapsed().as_secs_f64().max(0.001)
            );
        }
    });
    {
        // Output first, then the .done list: a hard kill can only duplicate lines.
        let mut g = w.lock().unwrap();
        g.0.flush().ok();
        if let Some(d) = g.1.as_mut() {
            d.flush().ok();
        }
    }
    let n = done.load(Ordering::Relaxed);
    eprintln!(
        "[{tag}] {} lines from {n} files in {:.1}s; {} files left ({})",
        written.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64(),
        total - n,
        if n == total { "complete" } else { "incomplete: run again with --resume" }
    );
}

// ------------------------------------------------------------------ databases


fn parse_tlsh(s: &str) -> Option<Tlsh> {
    let s = s.trim().trim_matches('"');
    let s = s.split(':').next().unwrap_or(s).trim(); // tlsh_db lines look like "T1...:n/a"
    let s = if s.len() == 70 && !s.starts_with("T1") && !s.starts_with("t1") { format!("T1{s}") } else { s.to_string() };
    s.to_ascii_uppercase().parse::<Tlsh>().ok()
}

/// Reads CSV from `hash` (sha256,tlsh,size,path), JSONL ({"sha256","tlsh","size"}), or
/// plain lists (any line containing a TLSH field).
fn load_db(path: &Path) -> Vec<Rec> {
    let Ok(f) = File::open(path) else {
        eprintln!("[tlsh] cannot open {}", path.display());
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("sha256,") {
            continue;
        }
        if line.starts_with('{') {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if let Some(t) = v["tlsh"].as_str().and_then(parse_tlsh) {
                let fp = serde_json::from_value::<Fingerprint>(v["fp"].clone()).ok();
                let apk = serde_json::from_value::<ApkFp>(v["apk"].clone()).ok();
                let size = fp.as_ref().map(|f| f.size).or(apk.as_ref().map(|a| a.size));
                let st = fp.map(Structure::Pe).or(apk.map(Structure::Apk));
                out.push(Rec {
                    sha256: v["sha256"].as_str().unwrap_or("").to_ascii_lowercase(),
                    tlsh: t,
                    size: v["size"].as_u64().or(size).unwrap_or(0),
                    path: v["path"].as_str().unwrap_or("").to_string(),
                    st,
                });
            }
            continue;
        }
        let cols: Vec<&str> = line.split([',', '\t', ':', ' ']).collect();
        if let Some(t) = cols.iter().find_map(|c| (c.trim().trim_matches('"').len() >= 70).then(|| parse_tlsh(c)).flatten()) {
            let sha = cols.iter().map(|c| c.trim().trim_matches('"')).find(|c| c.len() == 64 && c.chars().all(|x| x.is_ascii_hexdigit())).unwrap_or("");
            out.push(Rec { sha256: sha.to_ascii_lowercase(), tlsh: t, size: 0, path: String::new(), st: None });
        }
    }
    out
}

fn load_any(inputs: &[PathBuf], max_mb: u64) -> Vec<Rec> {
    let (dbs, dirs): (Vec<PathBuf>, Vec<PathBuf>) = inputs.iter().cloned().partition(|p| {
        p.is_file() && matches!(p.extension().and_then(|e| e.to_str()), Some("csv" | "jsonl" | "txt"))
    });
    let mut v: Vec<Rec> = dbs.iter().flat_map(|p| load_db(p)).collect();
    if !dirs.is_empty() {
        v.extend(hash_paths(&dirs, max_mb));
    }
    v
}

// ------------------------------------------------------------------ commands

fn out_writer(path: &Option<PathBuf>) -> Box<dyn Write> {
    match path {
        Some(p) => Box::new(BufWriter::new(File::create(p).expect("cannot create output"))),
        None => Box::new(BufWriter::new(std::io::stdout())),
    }
}

fn cmd_hash(paths: &[PathBuf], output: &Option<PathBuf>, jsonl: bool, dex: bool, max_mb: u64, opts: &RunOpts) {
    let max = max_mb * 1024 * 1024;
    let line = |r: Rec| {
        if jsonl {
            format!("{{\"sha256\":\"{}\",\"tlsh\":\"{}\",\"size\":{}}}", r.sha256, r.tlsh, r.size)
        } else {
            format!("{},{},{},\"{}\"", r.sha256, r.tlsh, r.size, r.path.replace('"', "\"\""))
        }
    };
    let header = (!jsonl).then_some("sha256,tlsh,size,path");
    match output {
        Some(o) => run_resumable("hash", paths, o, header, opts, |p| hash_file_opt(p, max, dex).map(line)),
        None => {
            if dex {
                eprintln!("--dex needs -o <output>");
                std::process::exit(2);
            }
            let recs = hash_paths(paths, max_mb);
            let mut w = out_writer(&None);
            if let Some(h) = header {
                writeln!(w, "{h}").unwrap();
            }
            for r in recs {
                writeln!(w, "{}", line(r)).unwrap();
            }
        }
    }
}

/// MalwareBazaar full.csv: the TLSH column is found by shape (T1 + 70 hex), so column
/// order changes do not matter.
fn read_mb_csv(path: &Path) -> Vec<Tlsh> {
    let Ok(f) = File::open(path) else { return Vec::new() };
    BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            l.split(',')
                .map(|c| c.trim().trim_matches('"').trim())
                .find(|c| c.len() == 72 && (c.starts_with("T1") || c.starts_with("t1")))
                .and_then(parse_tlsh)
        })
        .collect()
}

fn cmd_blacklist(paths: &[PathBuf], mb_csv: &[PathBuf], merge: &[PathBuf], output: &Path, max_mb: u64) {
    let mut set: HashSet<String> = HashSet::new();
    if !paths.is_empty() {
        for r in hash_paths(paths, max_mb) {
            set.insert(r.tlsh.to_string());
        }
    }
    for p in mb_csv {
        let v = read_mb_csv(p);
        eprintln!("[tlsh] {} digests from {}", v.len(), p.display());
        set.extend(v.into_iter().map(|t| t.to_string()));
    }
    for p in merge {
        let v = load_db(p);
        eprintln!("[tlsh] {} digests merged from {}", v.len(), p.display());
        set.extend(v.into_iter().map(|r| r.tlsh.to_string()));
    }
    let mut lines: Vec<String> = set.into_iter().collect();
    lines.sort();
    let mut w = BufWriter::new(File::create(output).expect("cannot create output"));
    writeln!(w, "# TLSH blacklist for tlsh_signatures/tlsh_blacklist.txt ({} digests)", lines.len()).unwrap();
    for l in &lines {
        writeln!(w, "{l}").unwrap();
    }
    eprintln!("[tlsh] wrote {} unique digests to {}", lines.len(), output.display());
}

fn cmd_compare(target: &str, dbs: &[PathBuf], max_dist: u32, top: usize) {
    let q = parse_tlsh(target).or_else(|| {
        let data = std::fs::read(target).ok()?;
        tlsh::hash_buf(&data).ok()
    });
    let Some(q) = q else {
        eprintln!("[tlsh] {target}: not a TLSH digest, and the file could not be hashed");
        std::process::exit(2);
    };
    let db: Vec<Rec> = dbs.iter().flat_map(|p| load_db(p)).collect();
    let started = Instant::now();
    let mut hits: Vec<(u32, &Rec)> = db.par_iter().filter_map(|r| {
        let d = q.compare(&r.tlsh);
        (d <= max_dist).then_some((d, r))
    }).collect();
    hits.sort_by_key(|h| h.0);
    println!("query {q}");
    println!("{} digests searched in {:.1} ms", db.len(), started.elapsed().as_secs_f64() * 1e3);
    for (d, r) in hits.into_iter().take(top) {
        println!("{d:>4}  {}  {}", r.tlsh, if r.sha256.is_empty() { "-" } else { &r.sha256 });
    }
}

fn cmd_refs(paths: &[PathBuf], output: &Path, max_mb: u64, opts: &RunOpts) {
    let max = max_mb * 1024 * 1024;
    run_resumable("refs", paths, output, None, opts, |p| {
        let meta = std::fs::metadata(p).ok()?;
        if meta.len() < 64 || meta.len() > max {
            return None;
        }
        let data = std::fs::read(p).ok()?;
        if !data.starts_with(b"MZ") && !data.starts_with(b"PK\x03\x04") {
            return None;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| analyzer::analyze_light(&data, &name))).ok()?;
        let v = serde_json::to_value(&report).ok()?;
        // PE: file TLSH + PE fingerprint. APK: DEX TLSH + manifest/signer fingerprint.
        let (tlsh, fp, apk) = match Structure::from_report(&v)? {
            Structure::Pe(fp) => (report.hashes.tlsh.clone()?, Some(fp), None),
            Structure::Apk(a) => (report.hashes.dex_tlsh.clone()?, None, Some(a)),
        };
        let rel = paths
            .iter()
            .filter(|root| root.extension().and_then(|e| e.to_str()) != Some("lst"))
            .find_map(|root| {
                p.strip_prefix(root)
                    .ok()
                    .map(|r| format!("{}/{}", root.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(), r.display()))
            })
            .unwrap_or_else(|| p.display().to_string());
        serde_json::to_string(&RefLine { sha256: report.hashes.sha256.clone(), tlsh, fp, apk, path: rel }).ok()
    });
}

fn cmd_tune(clean: &[PathBuf], malware: &[PathBuf], max_mb: u64, report_dist: u32, report: &Option<PathBuf>) {
    let clean = load_any(clean, max_mb);
    let mal = load_any(malware, max_mb);
    eprintln!("[tlsh] tuning: {} clean x {} malware", clean.len(), mal.len());
    let started = Instant::now();
    // (nearest distance, malware idx, nearest clean idx, clean idx the FULL rule would accept)
    let nearest: Vec<(u32, usize, Option<usize>, Option<(usize, u32)>)> = mal
        .par_iter()
        .enumerate()
        .map(|(i, m)| {
            let mut best: Option<(u32, usize)> = None;
            let mut close: Vec<(u32, usize)> = Vec::new();
            for (j, c) in clean.iter().enumerate() {
                let d = m.tlsh.compare(&c.tlsh);
                if best.is_none_or(|b| d < b.0) {
                    best = Some((d, j));
                }
                if d <= SMART_WL_MAX_DIST {
                    close.push((d, j));
                }
            }
            close.sort_by_key(|x| x.0);
            let accepted = m.st.as_ref().and_then(|ms| {
                close.iter().find_map(|&(d, j)| accept(d, ms, clean[j].st.as_ref()?).ok().map(|_| (j, d)))
            });
            (best.map(|b| b.0).unwrap_or(u32::MAX), i, best.map(|b| b.1), accepted)
        })
        .collect();
    eprintln!("[tlsh] {} comparisons in {:.1}s", clean.len() * mal.len(), started.elapsed().as_secs_f64());
    println!("Malware files whose closest clean file is within distance D");
    println!("(these would be at risk if the smart-whitelist limit were D):");
    for d in [5, 10, 15, 20, 30, 50, 80] {
        let n = nearest.iter().filter(|x| x.0 <= d).count();
        println!("  D <= {d:>3}: {n:>8} of {}  ({:.3}%)", mal.len(), 100.0 * n as f64 / mal.len().max(1) as f64);
    }
    let with_fp = mal.iter().filter(|m| m.st.is_some()).count();
    let clean_fp = clean.iter().filter(|c| c.st.is_some()).count();
    if with_fp > 0 && clean_fp > 0 {
        let accepted = nearest.iter().filter(|x| x.3.is_some()).count();
        println!();
        println!("FULL server rule (distance <= {SMART_WL_MAX_DIST}; PE: <= {SMART_WL_MAX_DIST_EP_MOVED} if the entry point moved + injection guard; APK: same signer/package + guard):");
        println!("  malware that would be WRONGLY whitelisted: {accepted} of {with_fp} PE/APK  ({:.4}%)", 100.0 * accepted as f64 / with_fp.max(1) as f64);
        if accepted > 0 {
            println!("  -> inspect them with --report; remove the matching clean references or lower the limits.");
        }
    } else {
        println!();
        println!("(Use `refs` JSONL files for --clean and --malware to also test the full server rule.)");
    }
    if let Some(p) = report {
        let mut w = BufWriter::new(File::create(p).expect("cannot create report"));
        writeln!(w, "distance,malware_sha256,malware_path,clean_sha256,clean_path,would_be_whitelisted").unwrap();
        let mut close: Vec<_> = nearest.iter().filter(|x| x.0 <= report_dist || x.3.is_some()).collect();
        close.sort_by_key(|x| x.0);
        for (d, i, j, acc) in close {
            let j = &acc.map(|a| a.0).or(*j);
            let m = &mal[*i];
            let c = j.map(|j| &clean[j]);
            writeln!(
                w,
                "{d},{},\"{}\",{},\"{}\",{}",
                m.sha256,
                m.path,
                c.map(|c| c.sha256.as_str()).unwrap_or(""),
                c.map(|c| c.path.as_str()).unwrap_or(""),
                acc.is_some()
            )
            .unwrap();
        }
        eprintln!("[tlsh] wrote {}", p.display());
    }
}

fn main() {
    let cli = Cli::parse();
    if let Some(n) = cli.threads {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().ok();
    }
    let opts = RunOpts { deadline: cli.deadline, resume: cli.resume };
    match &cli.cmd {
        Cmd::Hash { paths, output, jsonl, dex, max_mb } => cmd_hash(paths, output, *jsonl, *dex, *max_mb, &opts),
        Cmd::Blacklist { paths, mb_csv, merge, output, max_mb } => cmd_blacklist(paths, mb_csv, merge, output, *max_mb),
        Cmd::Compare { target, db, max_dist, top } => cmd_compare(target, db, *max_dist, *top),
        Cmd::Refs { paths, output, max_mb } => cmd_refs(paths, output, *max_mb, &opts),
        Cmd::Tune { clean, malware, max_mb, report_dist, report } => cmd_tune(clean, malware, *max_mb, *report_dist, report),
    }
}
