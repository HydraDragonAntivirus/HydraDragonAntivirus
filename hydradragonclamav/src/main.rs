use hydradragonclamav::{Engine, LoadReport, ScanOptions};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug)]
struct Cli {
    database: PathBuf,
    scan: Option<PathBuf>,
    strict_targets: bool,
    max_matches: usize,
    scan_archives: bool,
    scan_normalized: bool,
    max_recursion: usize,
    max_child_objects: usize,
    max_child_size: usize,
    show_unsupported: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(found) => {
            if found {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let cli = parse_args()?;
    let (engine, report) = Engine::from_database_dir(&cli.database)?;
    print_report(&report);

    if cli.show_unsupported {
        for item in &engine.database.unsupported {
            println!(
                "unsupported: {}:{} {}",
                item.source.path.display(),
                item.source.line,
                item.reason
            );
        }
    }

    let Some(scan_path) = cli.scan else {
        return Ok(false);
    };

    let options = ScanOptions {
        strict_targets: cli.strict_targets,
        max_matches: cli.max_matches,
        scan_archives: cli.scan_archives,
        scan_normalized: cli.scan_normalized,
        max_recursion: cli.max_recursion,
        max_child_objects: cli.max_child_objects,
        max_child_size: cli.max_child_size,
        ..ScanOptions::default()
    };
    let mut files = Vec::new();
    collect_scan_files(&scan_path, &mut files)?;
    let mut any_found = false;
    for file in files {
        let matches = engine.scan_path(&file, options)?;
        if matches.is_empty() {
            println!("{}: OK", file.display());
        } else {
            any_found = true;
            for hit in matches {
                println!(
                    "{}: {} FOUND ({:?}, object={}, view={:?}, {}:{})",
                    file.display(),
                    hit.name,
                    hit.kind,
                    hit.object_path,
                    hit.view,
                    hit.source.path.display(),
                    hit.source.line
                );
            }
        }
    }
    Ok(any_found)
}

fn parse_args() -> Result<Cli, String> {
    let mut cli = Cli {
        database: default_database_path(),
        scan: None,
        strict_targets: false,
        max_matches: 128,
        scan_archives: true,
        scan_normalized: true,
        max_recursion: 8,
        max_child_objects: 4096,
        max_child_size: 128 * 1024 * 1024,
        show_unsupported: false,
    };

    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-d" | "--database" => {
                index += 1;
                cli.database = args
                    .get(index)
                    .map(PathBuf::from)
                    .ok_or_else(|| "--database requires a path".to_string())?;
            }
            "-s" | "--scan" => {
                index += 1;
                cli.scan = Some(
                    args.get(index)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--scan requires a path".to_string())?,
                );
            }
            "--strict-targets" => cli.strict_targets = true,
            "--no-archives" => cli.scan_archives = false,
            "--no-normalize" => cli.scan_normalized = false,
            "--max-matches" => {
                index += 1;
                cli.max_matches = args
                    .get(index)
                    .ok_or_else(|| "--max-matches requires a number".to_string())?
                    .parse::<usize>()
                    .map_err(|_| "--max-matches requires a decimal number".to_string())?;
            }
            "--max-recursion" => {
                index += 1;
                cli.max_recursion = parse_usize_arg(&args, index, "--max-recursion")?;
            }
            "--max-child-objects" => {
                index += 1;
                cli.max_child_objects = parse_usize_arg(&args, index, "--max-child-objects")?;
            }
            "--max-child-size" => {
                index += 1;
                cli.max_child_size = parse_size_arg(&args, index, "--max-child-size")?;
            }
            "--list-unsupported" => cli.show_unsupported = true,
            other if cli.scan.is_none() => cli.scan = Some(PathBuf::from(other)),
            other => return Err(format!("unknown argument '{other}'")),
        }
        index += 1;
    }

    Ok(cli)
}

fn print_help() {
    println!(
        "hydradragonclamav\n\n  --database, -d <path>     ClamAV database directory\n  --scan, -s <path>         File or directory to scan\n  --strict-targets          Enforce simple target type checks on raw objects\n  --no-archives             Disable recursive archive scanning\n  --no-normalize            Disable HTML/text normalized views\n  --max-matches <n>         Stop after n matches per scanned file\n  --max-recursion <n>       Archive recursion depth, default 8\n  --max-child-objects <n>   Child object scan limit, default 4096\n  --max-child-size <size>   Child size limit, supports K/M/G suffixes\n  --list-unsupported        Print unsupported database records\n\nWithout --scan, the command loads the database and prints coverage stats."
    );
}

fn parse_usize_arg(args: &[String], index: usize, name: &str) -> Result<usize, String> {
    args.get(index)
        .ok_or_else(|| format!("{name} requires a number"))?
        .parse::<usize>()
        .map_err(|_| format!("{name} requires a decimal number"))
}

fn parse_size_arg(args: &[String], index: usize, name: &str) -> Result<usize, String> {
    let raw = args
        .get(index)
        .ok_or_else(|| format!("{name} requires a size"))?;
    let (number, multiplier) = match raw.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&raw[..raw.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&raw[..raw.len() - 1], 1024usize * 1024),
        Some(b'g' | b'G') => (&raw[..raw.len() - 1], 1024usize * 1024 * 1024),
        _ => (raw.as_str(), 1usize),
    };
    number
        .parse::<usize>()
        .map(|value| value.saturating_mul(multiplier))
        .map_err(|_| format!("{name} requires a decimal size"))
}

fn default_database_path() -> PathBuf {
    let direct = PathBuf::from("HydraDragonAVPortable").join("database");
    if direct.exists() {
        return direct;
    }
    PathBuf::from("..")
        .join("HydraDragonAVPortable")
        .join("database")
}

fn print_report(report: &LoadReport) {
    println!("database files: {}", report.files_seen);
    println!("signature lines: {}", report.lines_seen);
    println!(
        "loaded extended body signatures: {}",
        report.extended_loaded
    );
    println!("loaded logical signatures: {}", report.logical_loaded);
    println!(
        "loaded container metadata signatures: {}",
        report.container_loaded
    );
    println!("loaded file-type magic records: {}", report.ftm_loaded);
    println!("loaded bytecode programs: {}", report.bytecodes_loaded);
    println!("skipped hash database files: {}", report.hash_files_skipped);
    println!("unsupported database files: {}", report.unsupported_files);
    println!("unsupported records: {}", report.unsupported_records);
    println!("parse errors: {}", report.errors.len());
    if !report.errors.is_empty() {
        for error in report.errors.iter().take(20) {
            println!(
                "parse error: {}:{} {}",
                error.source.path.display(),
                error.source.line,
                error.message
            );
        }
        if report.errors.len() > 20 {
            println!("parse error: ... {} more", report.errors.len() - 20);
        }
    }
}

fn collect_scan_files(path: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_scan_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}
