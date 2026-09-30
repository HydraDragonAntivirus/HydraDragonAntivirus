use std::path::{Path, PathBuf};
use std::process::ExitCode;

use openedr_sdk_example::{default_portable_dir, OpenEdrScanner};
use serde_json::Value;

const FLAGGED: &[&str] = &["Malicious", "Suspicious", "Error"];

fn print_help() {
    eprintln!(
        "openedr-cli — scan with openedr_static.dll

USAGE:
  openedr-cli [--dll PATH] [--rules DIR] [--json] <command> [args]

COMMANDS:
  scan <path> [-r]     scan a file or directory
  bytes <path>         scan file contents via scan_bytes
  url <url>            scan a URL
  registry <path>      check a registry path against PUA rules
  evtx <path>          scan an EVTX log with Hayabusa rules
  events               scan live Windows event logs
  hosts [--restore]    check or restore the hosts file

DLL and rules default to the directory next to this exe
(OpenMalwareScannerPortable layout). Exit 1 = Malicious/Suspicious."
    );
}

struct Opts {
    dll: Option<PathBuf>,
    rules: Option<PathBuf>,
    json: bool,
    args: Vec<String>,
}

fn parse_opts() -> Result<Opts, String> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        std::process::exit(0);
    }
    let mut dll = None;
    let mut rules = None;
    let mut json = false;
    let mut args = Vec::new();
    while !raw.is_empty() {
        let a = raw.remove(0);
        match a.as_str() {
            "--dll" => {
                dll = Some(PathBuf::from(raw.first().ok_or("--dll needs a path")?));
                raw.remove(0);
            }
            "--rules" => {
                rules = Some(PathBuf::from(raw.first().ok_or("--rules needs a path")?));
                raw.remove(0);
            }
            "--json" => json = true,
            _ => args.push(a),
        }
    }
    if args.is_empty() {
        return Err("missing command".into());
    }
    Ok(Opts {
        dll,
        rules,
        json,
        args,
    })
}

fn flagged(report: &Value) -> bool {
    report
        .get("verdict")
        .and_then(|v| v.as_str())
        .map(|v| FLAGGED.contains(&v))
        .unwrap_or(false)
}

fn print_report(raw: &str, as_json: bool) {
    if as_json {
        println!("{raw}");
        return;
    }
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        println!("{raw}");
        return;
    };
    if v.get("error").and_then(|e| e.as_bool()) == Some(true) {
        println!("{raw}");
        return;
    }
    let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("Unknown");
    let score = v
        .get("max_threat_score")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0);
    let sha = v.get("sha256").and_then(|x| x.as_str()).unwrap_or("");
    let target = v
        .get("target")
        .or_else(|| v.get("target_url"))
        .or_else(|| v.get("query_path"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    print!("{verdict} score={score}");
    if !sha.is_empty() {
        print!(" {sha}");
    }
    if !target.is_empty() {
        print!(" {target}");
    }
    println!();
    if let Some(signer) = v.get("signer_info") {
        println!(
            "  signer  trusted={} catalog={} status={} name={}",
            signer.get("is_trusted").unwrap_or(&Value::Null),
            signer.get("is_catalog_signed").unwrap_or(&Value::Null),
            signer.get("status").and_then(|x| x.as_str()).unwrap_or(""),
            signer
                .get("signer_name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
        );
    }
    if let Some(dets) = v.get("detections").and_then(|d| d.as_array()) {
        if !dets.is_empty() {
            println!("  detections ({}):", dets.len());
            for det in dets {
                let extra = det
                    .get("details")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                println!(
                    "    [{}] {} ({}){}",
                    det.get("layer").and_then(|x| x.as_str()).unwrap_or(""),
                    det.get("name").and_then(|x| x.as_str()).unwrap_or(""),
                    det.get("score").unwrap_or(&Value::Null),
                    if extra.is_empty() {
                        String::new()
                    } else {
                        format!(" — {extra}")
                    }
                );
            }
        }
    }
    if let Some(p) = v.get("malware_probability").and_then(|x| x.as_f64()) {
        println!("  malware_probability={p}");
    }
    if let Some(ms) = v.get("scan_time_ms") {
        println!("  scan_time_ms={ms}");
    }
}

fn walk_files(root: &Path, recursive: bool) -> Result<Vec<PathBuf>, String> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !root.is_dir() {
        return Err(format!("not found: {}", root.display()));
    }
    let mut out = Vec::new();
    if recursive {
        fn rec(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        rec(&p, out);
                    } else if p.is_file() {
                        out.push(p);
                    }
                }
            }
        }
        rec(root, &mut out);
    } else if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn run() -> Result<u8, String> {
    let opts = parse_opts().map_err(|e| {
        print_help();
        e
    })?;
    let portable = default_portable_dir();
    let dll = opts
        .dll
        .unwrap_or_else(|| portable.join("openedr_static.dll"));
    let rules = opts.rules.unwrap_or(portable);
    let scanner = OpenEdrScanner::load(&dll, Some(&rules))?;
    let cmd = opts.args[0].as_str();
    let rest = &opts.args[1..];
    match cmd {
        "scan" => {
            let path = rest.first().ok_or("scan needs a path")?;
            let recursive = rest.iter().any(|a| a == "-r" || a == "--recursive");
            let files = walk_files(Path::new(path), recursive)?;
            let mut hit = false;
            let mut reports = Vec::new();
            for f in files {
                let raw = scanner.scan_file(&f)?;
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    if flagged(&v) {
                        hit = true;
                    }
                    reports.push(v);
                }
                if !opts.json {
                    print_report(&raw, false);
                }
            }
            if opts.json {
                if reports.len() == 1 {
                    println!("{}", serde_json::to_string_pretty(&reports[0]).unwrap());
                } else {
                    println!("{}", serde_json::to_string_pretty(&reports).unwrap());
                }
            }
            Ok(if hit { 1 } else { 0 })
        }
        "bytes" => {
            let path = rest.first().ok_or("bytes needs a path")?;
            let data = std::fs::read(path).map_err(|e| e.to_string())?;
            let name = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str());
            let raw = scanner.scan_bytes(&data, name);
            print_report(&raw, opts.json);
            let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            Ok(if flagged(&v) { 1 } else { 0 })
        }
        "url" => {
            let url = rest.first().ok_or("url needs a URL")?;
            let raw = scanner.scan_url(url)?;
            print_report(&raw, opts.json);
            let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            Ok(if flagged(&v) { 1 } else { 0 })
        }
        "registry" => {
            let path = rest.first().ok_or("registry needs a path")?;
            let raw = scanner.check_registry(path)?;
            print_report(&raw, opts.json);
            let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let hit = v.get("is_pua_autostart").and_then(|x| x.as_bool()) == Some(true)
                || v.get("matched_patterns")
                    .and_then(|x| x.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
            Ok(if hit { 1 } else { 0 })
        }
        "evtx" => {
            let path = rest.first().ok_or("evtx needs a path")?;
            let raw = scanner.scan_evtx(Path::new(path))?;
            print_report(&raw, opts.json);
            Ok(0)
        }
        "events" => {
            let raw = scanner.scan_system_events();
            print_report(&raw, opts.json);
            Ok(0)
        }
        "hosts" => {
            let restore = rest.iter().any(|a| a == "--restore");
            let no_backup = rest.iter().any(|a| a == "--no-backup");
            let custom = rest
                .windows(2)
                .find(|w| w[0] == "--path")
                .map(|w| PathBuf::from(&w[1]));
            let raw = if restore {
                scanner.restore_hosts_file(custom.as_deref(), !no_backup)
            } else {
                scanner.check_hosts_file(custom.as_deref())
            };
            print_report(&raw, opts.json);
            Ok(0)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
