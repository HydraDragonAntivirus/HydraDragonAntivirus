use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use yara_x::{Compiler, Rules, Scanner};

struct Args {
    rules: PathBuf,
    target: PathBuf,
    out: PathBuf,
    offset: u64,
    length: Option<u64>,
    limit_rules: usize,
    timeout_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut rules = None;
    let mut target = None;
    let mut out = None;
    let mut offset = 0u64;
    let mut length = None;
    let mut limit_rules = usize::MAX;
    let mut timeout_secs = 0u64;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--rules" => {
                i += 1;
                rules = argv.get(i).map(PathBuf::from);
            }
            "--target" => {
                i += 1;
                target = argv.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = argv.get(i).map(PathBuf::from);
            }
            "--offset" => {
                i += 1;
                offset = argv
                    .get(i)
                    .ok_or("--offset needs a value")?
                    .parse()
                    .map_err(|_| "bad --offset")?;
            }
            "--length" => {
                i += 1;
                length = Some(
                    argv.get(i)
                        .ok_or("--length needs a value")?
                        .parse()
                        .map_err(|_| "bad --length")?,
                );
            }
            "--limit-rules" => {
                i += 1;
                limit_rules = argv
                    .get(i)
                    .ok_or("--limit-rules needs a value")?
                    .parse()
                    .map_err(|_| "bad --limit-rules")?;
            }
            "--timeout" => {
                i += 1;
                timeout_secs = argv
                    .get(i)
                    .ok_or("--timeout needs a value")?
                    .parse()
                    .map_err(|_| "bad --timeout")?;
            }
            "-h" | "--help" => {
                println!(
                    "yxscan --rules <r.yar> --target <file> [--out hits.txt] [--offset N] \
                     [--length N] [--limit-rules N] [--timeout secs]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }

    Ok(Args {
        rules: rules.ok_or("--rules is required")?,
        target: target.ok_or("--target is required")?,
        out: out.unwrap_or_else(|| PathBuf::from("yxscan_hits.txt")),
        offset,
        length,
        limit_rules,
        timeout_secs,
    })
}

fn read_range(path: &Path, offset: u64, length: Option<u64>) -> std::io::Result<(Vec<u8>, u64)> {
    let mut file = File::open(path)?;
    let total = file.metadata()?.len();
    if offset > 0 {
        file.seek(SeekFrom::Start(offset))?;
    }
    let cap = match length {
        Some(l) => std::cmp::min(l, total.saturating_sub(offset)),
        None => total - offset,
    };
    let mut buf = Vec::with_capacity(std::cmp::min(cap, 512 * 1024 * 1024) as usize);
    file.take(cap).read_to_end(&mut buf)?;
    Ok((buf, cap))
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(2);
        }
    };

    let rules = {
        let t = Instant::now();
        // 1. Check if user provided a .yrc directly or if a corresponding .yrc exists next to the .yar
        let yrc_candidate = if args.rules.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("yrc")).unwrap_or(false) {
            Some(args.rules.clone())
        } else {
            let candidate = args.rules.with_extension("yrc");
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        };

        let mut loaded_rules: Option<Rules> = None;

        if let Some(ref yrc_path) = yrc_candidate {
            if let Ok(raw_bytes) = std::fs::read(yrc_path) {
                if let Ok(r) = Rules::deserialize(&raw_bytes) {
                    eprintln!("[1/3] loaded pre-compiled rules: {}", yrc_path.display());
                    eprintln!(
                        "      size: {:.1} MB, loaded in {:.3}s, total rules = {}",
                        raw_bytes.len() as f64 / 1048576.0,
                        t.elapsed().as_secs_f64(),
                        r.iter().count()
                    );
                    loaded_rules = Some(r);
                }
            }
        }

        if let Some(r) = loaded_rules {
            r
        } else {
            // Check if args.rules itself is already binary serialized rules
            if let Ok(raw_bytes) = std::fs::read(&args.rules) {
                if let Ok(r) = Rules::deserialize(&raw_bytes) {
                    eprintln!("[1/3] loaded pre-compiled rules directly from {}", args.rules.display());
                    eprintln!(
                        "      size: {:.1} MB, loaded in {:.3}s, total rules = {}",
                        raw_bytes.len() as f64 / 1048576.0,
                        t.elapsed().as_secs_f64(),
                        r.iter().count()
                    );
                    r
                } else {
                    // Need to compile from source
                    eprintln!("[1/3] compiling rules from source: {}", args.rules.display());
                    let source = match String::from_utf8(raw_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("ERROR: cannot read rules file as UTF-8: {e}");
                            std::process::exit(2);
                        }
                    };
                    eprintln!(
                        "      source: {:.1} MB, read in {:.2}s",
                        source.len() as f64 / 1048576.0,
                        t.elapsed().as_secs_f64()
                    );

                    let mut compiler = Compiler::new();
                    if let Err(e) = compiler.add_source(source.as_str()) {
                        eprintln!("ERROR: compile failed: {e}");
                        std::process::exit(2);
                    }
                    let r = compiler.build();
                    eprintln!(
                        "      compiled in {:.2}s, total rules = {}",
                        t.elapsed().as_secs_f64(),
                        r.iter().count()
                    );

                    // Auto-save compiled .yrc next to the rules file for next runs!
                    let auto_yrc = args.rules.with_extension("yrc");
                    if let Ok(serialized) = r.serialize() {
                        if std::fs::write(&auto_yrc, &serialized).is_ok() {
                            eprintln!("      cached pre-compiled rules to {}", auto_yrc.display());
                        }
                    }

                    r
                }
            } else {
                eprintln!("ERROR: cannot open rules file: {}", args.rules.display());
                std::process::exit(2);
            }
        }
    };

    eprintln!("[2/3] loading target: {}", args.target.display());
    let t = Instant::now();
    let (data, expected) = match read_range(&args.target, args.offset, args.length) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: cannot read target: {e}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "      loaded {:.2} GB in {:.1}s",
        data.len() as f64 / 1073741824.0,
        t.elapsed().as_secs_f64()
    );

    eprintln!("[3/3] scanning ...");
    let mut scanner = Scanner::new(&rules);
    scanner.max_matches_per_pattern(1_000_000);
    if args.timeout_secs > 0 {
        scanner.set_timeout(std::time::Duration::from_secs(args.timeout_secs));
    }

    let t = Instant::now();
    let results = match scanner.scan(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: scan failed: {e}");
            std::process::exit(2);
        }
    };
    let elapsed = t.elapsed().as_secs_f64();

    let mbs = if elapsed > 0.0 {
        data.len() as f64 / 1048576.0 / elapsed
    } else {
        0.0
    };

    let mut rows: Vec<String> = Vec::new();
    let mut matching = 0usize;
    for r in results.matching_rules() {
        matching += 1;
        if rows.len() >= args.limit_rules {
            continue;
        }
        let id = r.identifier();
        let ns = r.namespace();
        let npat = r.patterns().filter(|p| !p.is_private()).count();
        let tags: Vec<String> = r.tags().map(|t| t.identifier().to_string()).collect();
        rows.push(format!(
            "{id}\tns={ns}\tpatterns={npat}\ttags={}",
            if tags.is_empty() {
                "-".to_string()
            } else {
                tags.join(",")
            }
        ));
    }
    rows.sort();
    rows.dedup();

    let file = File::create(&args.out).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot create {}: {e}", args.out.display());
        std::process::exit(2);
    });
    let mut w = std::io::BufWriter::new(file);
    writeln!(
        w,
        "# yara-x scan report\n# rules   : {}\n# target  : {}\n# range   : offset={} len={} \
         (of {})\n# elapsed : {:.1}s\n# throughput: {:.1} MB/s\n# matching rules (incl. private): {}\n# unique rule ids written: {}\n",
        args.rules.display(),
        args.target.display(),
        args.offset,
        expected,
        args.target
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0),
        elapsed,
        mbs,
        matching,
        rows.len()
    )
    .unwrap();
    for row in &rows {
        writeln!(w, "{row}").unwrap();
    }
    w.flush().unwrap();

    eprintln!(
        "done in {:.1}s ({:.1} MB/s); matching rules = {}; unique = {}",
        elapsed,
        mbs,
        matching,
        rows.len()
    );
    eprintln!("report: {}", args.out.display());
}
