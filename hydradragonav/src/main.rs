#![cfg(windows)]

use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use hydradragonav::disinfector::{self, DisinfectOutcome};
use hydradragonav::memory_scanner;
use hydradragonav::pipeline::scan_hayabusa_once;
use hydradragonav::pipeline::{Pipeline, PipelineConfig, ScanCategory};
use hydradragonav::registry_scanner::RegistryScanner;
use hydradragonav::remediation;
use hydradragonav::settings::Settings;

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn resolve_bloom_dir() -> PathBuf {
    std::env::var("BLOOM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("bloom_filter"))
}

fn resolve_yara_dir() -> PathBuf {
    std::env::var("YARA_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("yara-x"))
}

fn resolve_hydradragonsig_rules_dir() -> PathBuf {
    std::env::var("HYDRADRAGONSIG_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("hydradragonsig_rules"))
}

fn resolve_reglist() -> PathBuf {
    std::env::var("REGLIST_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("reglist.txt"))
}

fn resolve_clamav_db() -> PathBuf {
    std::env::var("CLAMAV_DATABASE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("database"))
}

fn resolve_hayabusa_dir() -> PathBuf {
    std::env::var("HAYABUSA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("hayabusa"))
}

fn resolve_pe_ml_model() -> PathBuf {
    std::env::var("PE_ML_MODEL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("ml").join("pe_model.mpk"))
}

fn resolve_js_ml_model() -> PathBuf {
    std::env::var("JS_ML_MODEL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe_dir().join("ml").join("js_model.mpk"))
}

#[derive(Parser)]
#[command(
    name = "hydradragonav",
    version,
    about = "Unified malware scanning engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, env = "CLAMAV_DATABASE", global = true)]
    db: Option<PathBuf>,

    #[arg(long, env = "BLOOM_DIR", global = true)]
    bloom_dir: Option<PathBuf>,

    #[arg(long, env = "YARA_RULES_DIR", global = true)]
    yara_dir: Option<PathBuf>,

    #[arg(long, env = "HYDRADRAGONSIG_RULES_DIR", global = true)]
    hydradragonsig_rules_dir: Option<PathBuf>,

    #[arg(long, env = "HAYABUSA_DIR", global = true)]
    hayabusa_dir: Option<PathBuf>,

    #[arg(long, env = "PE_ML_MODEL_PATH", global = true)]
    pe_ml_model: Option<PathBuf>,

    #[arg(long, env = "JS_ML_MODEL_PATH", global = true)]
    js_ml_model: Option<PathBuf>,

    #[arg(long, env = "ML_THRESHOLD", global = true, default_value_t = 0.95)]
    ml_threshold: f32,
}

#[derive(Subcommand)]
enum Command {
    /// Scan through the detection pipeline with custom categories
    Scan {
        /// Files/directories to scan (only used when --files category is active)
        #[arg()]
        paths: Vec<PathBuf>,

        /// Scan files and directories (ClamAV, YARA-X, ML, static analysis)
        #[arg(long)]
        files: bool,

        /// Scan running process memory
        #[arg(long)]
        memory: bool,

        /// Scan registry for PUMs and persistence
        #[arg(long)]
        registry: bool,

        /// Scan event logs with Sigma/Hayabusa rules
        #[arg(long)]
        sigma: bool,

        /// Scan for PUM (Potentially Unwanted Modifications)
        #[arg(long)]
        pum: bool,

        /// Output raw JSON (default: human-readable)
        #[arg(long, short)]
        json: bool,

        /// Write malware-only results to this file after directory scan
        #[arg(long)]
        output: Option<PathBuf>,

        /// Print per-engine timing and highlight the slowest engine
        #[arg(long)]
        time_engines: bool,

        /// Enable yara-x fast-scan mode
        #[arg(long, short, default_value_t = true)]
        fast_scan: bool,
    },

    /// Update Hayabusa detection rules
    Update,

    /// Print engine versions
    Version,

    /// Manage quarantined files (XOR-encoded, recoverable)
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Finish a disinfection that was deferred to reboot (invoked by the RunOnce
    /// key created when a locked/critical malware couldn't be cleaned live).
    DisinfectPending,

}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file to its original location (by id)
    Restore { id: String },
    /// Permanently delete a quarantined file (by id)
    Delete { id: String },
}

fn default_paths() -> (
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
) {
    (
        resolve_clamav_db(),
        resolve_bloom_dir(),
        resolve_yara_dir(),
        resolve_hydradragonsig_rules_dir(),
        resolve_hayabusa_dir(),
        resolve_pe_ml_model(),
        resolve_js_ml_model(),
        resolve_reglist(),
    )
}

struct FullConfig {
    db: PathBuf,
    bloom_dir: Option<PathBuf>,
    yara_dir: Option<PathBuf>,
    hydradragonsig_rules_dir: Option<PathBuf>,
    hayabusa_dir: Option<PathBuf>,
    pe_ml_model: Option<PathBuf>,
    js_ml_model: Option<PathBuf>,
    reglist: Option<PathBuf>,
    ml_threshold: f32,
}

fn severity_from_verdict(v: hydradragonav::verdict::Verdict) -> u8 {
    use hydradragonav::verdict::Verdict;
    match v {
        Verdict::Trusted | Verdict::Clean => 0,
        Verdict::Pua => 30,
        Verdict::Suspicious => 50,
        Verdict::Phishing => 75,
        Verdict::Malware => 100,
    }
}

fn severity_bar(sev: u8) -> String {
    let filled = (sev as u16).saturating_mul(10).min(1000) / 100;
    let empty = 10usize.saturating_sub(filled as usize);
    let bar: String = std::iter::repeat('█').take(filled as usize).chain(std::iter::repeat('░').take(empty)).collect();
    format!("{} {}%", bar, sev)
}

fn cmd_custom_scan(
    paths: &[PathBuf],
    categories: Vec<ScanCategory>,
    json: bool,
    output: Option<&std::path::Path>,
    time_engines: bool,
    fast_scan: bool,
    config: &FullConfig,
) {
    let cats = resolve_categories(categories);
    let has_cat = |c| cats.contains(&c);

    // Ensure the settings directory exists
    let settings_dir = Settings::settings_dir(&exe_dir());
    let _ = std::fs::create_dir_all(&settings_dir);

    let settings = Settings::load(&exe_dir());
    let excluded_dirs: Vec<PathBuf> = settings
        .excluded_dirs
        .iter()
        .map(|s| {
            let p = PathBuf::from(s);
            if p.is_relative() { exe_dir().join(&p) } else { p }
        })
        .filter(|p| p.exists())
        .collect();
    let excluded_files: Vec<PathBuf> = settings
        .excluded_files
        .iter()
        .map(|s| {
            let p = PathBuf::from(s);
            if p.is_relative() { exe_dir().join(&p) } else { p }
        })
        .filter(|p| p.exists())
        .collect();

    let pipeline_config = PipelineConfig {
        bloom_dir: config.bloom_dir.clone().filter(|p| p.exists()),
        yara_rules_dir: config.yara_dir.clone().filter(|p| p.exists()),
        hydradragonsig_rules_dir: config
            .hydradragonsig_rules_dir
            .clone()
            .filter(|p| p.exists()),
        pe_ml_model_path: config.pe_ml_model.clone().filter(|p| p.exists()),
        js_ml_model_path: config.js_ml_model.clone().filter(|p| p.exists()),
        clamav_db: Some(config.db.clone()).filter(|p| p.exists()),
        hayabusa_dir: config.hayabusa_dir.clone().filter(|p| p.exists()),
        scan_categories: cats.clone(),
        ml_threshold: config.ml_threshold,
        time_engines,
        fast_scan,
        excluded_dirs,
        excluded_files,
        ..Default::default()
    };

    let pipeline = Pipeline::new(pipeline_config);
    let mut harmful_results: Vec<(PathBuf, hydradragonav::verdict::ScanResult)> = Vec::new();
    let mut engine_totals: std::collections::HashMap<&'static str, u64> =
        std::collections::HashMap::new();

    // Non-file scans
    if has_cat(ScanCategory::Registry) || has_cat(ScanCategory::Pum) {
        if json {
            let reg_result = scan_registry(config);
            println!("{}", serde_json::to_string(&reg_result).unwrap());
        } else {
            print_registry_scan(&scan_registry(config));
        }
    }

    if has_cat(ScanCategory::Sigma) {
        if let Some(ref hdir) = config.hayabusa_dir {
            let hayabusa_matches = scan_hayabusa_once(hdir);
            if json {
                println!("{}", serde_json::to_value(&hayabusa_matches).unwrap());
            } else if !hayabusa_matches.is_empty() {
                println!("[Hayabusa]");
                for m in &hayabusa_matches {
                    println!("  ├─ [{}] {} ({})", m.severity, m.title, m.channel);
                }
            }
        }
    }

    if has_cat(ScanCategory::Memory) {
        if json {
            println!("{}", serde_json::to_value(memory_scanner::scan_process_memory(&pipeline)).unwrap());
        } else {
            print_memory_scan(&memory_scanner::scan_process_memory(&pipeline));
        }
    }

    // File scans
    if has_cat(ScanCategory::Files) && !paths.is_empty() {
        // Single scan (1 file, no dirs) → no progress bar
        let is_single_file = paths.len() == 1 && paths[0].is_file();
        if is_single_file {
            scan_and_print(paths[0].as_path(), &pipeline, json, &mut harmful_results, &mut engine_totals, time_engines);
        } else {
            scan_paths(paths, &pipeline, json, output, &mut harmful_results, &mut engine_totals, time_engines);
        }
    }

    if !json && !harmful_results.is_empty() {
        let infected: Vec<(PathBuf, Option<String>)> = harmful_results
            .iter()
            .map(|(p, r)| (p.clone(), r.threat_name.clone()))
            .collect();
        offer_disinfection(&infected, &pipeline, &config.db);
    }
}

fn resolve_categories(mut categories: Vec<ScanCategory>) -> Vec<ScanCategory> {
    if categories.is_empty() {
        let settings = Settings::load(&exe_dir());
        if !settings.default_categories.is_empty() {
            settings.default_categories.iter().filter_map(|s| {
                match s.to_lowercase().as_str() {
                    "files" => Some(ScanCategory::Files),
                    "memory" => Some(ScanCategory::Memory),
                    "registry" => Some(ScanCategory::Registry),
                    "sigma" => Some(ScanCategory::Sigma),
                    "pum" => Some(ScanCategory::Pum),
                    _ => { eprintln!("[Settings] Unknown category '{s}'"); None }
                }
            }).collect()
        } else {
            ScanCategory::all()
        }
    } else {
        let settings = Settings::load(&exe_dir());
        if settings.scan_with_registry {
            if !categories.contains(&ScanCategory::Registry) { categories.push(ScanCategory::Registry); }
            if !categories.contains(&ScanCategory::Pum) { categories.push(ScanCategory::Pum); }
        }
        if settings.scan_with_memory && !categories.contains(&ScanCategory::Memory) {
            categories.push(ScanCategory::Memory);
        }
        if settings.scan_with_sigma && !categories.contains(&ScanCategory::Sigma) {
            categories.push(ScanCategory::Sigma);
        }
        categories
    }
}

/// Scan a single file and print its result inline.
fn scan_and_print(
    path: &std::path::Path,
    pipeline: &Pipeline,
    json: bool,
    harmful_results: &mut Vec<(PathBuf, hydradragonav::verdict::ScanResult)>,
    engine_totals: &mut std::collections::HashMap<&'static str, u64>,
    _time_engines: bool,
) {
    let scan_start = Instant::now();
    let result = pipeline.scan_file(path);
    let elapsed = scan_start.elapsed();

    if json {
        println!("{}", serde_json::to_string(&serde_json::json!({
            "file": path.to_string_lossy(),
            "verdict": result.verdict.label(),
            "threat_name": result.threat_name,
            "engines": result.engines,
            "scan_time_ms": elapsed.as_millis(),
        })).unwrap());
    } else {
        let sev = severity_from_verdict(result.verdict);
        println!("[{}] {} ({:.0?})  severity: {}", result.verdict.label(), path.display(), elapsed, severity_bar(sev));
        if let Some(ref tn) = result.threat_name {
            println!("  threat: {}", tn);
        }
        for e in &result.engines {
            match e.elapsed_ms {
                Some(ms) => println!("  ├─ {}: {} ({}) [{} ms]", e.engine, e.verdict.label(), e.detail, ms),
                None => println!("  ├─ {}: {} ({})", e.engine, e.verdict.label(), e.detail),
            }
        }
        if let Some(prob) = result.ml_malware_probability {
            println!("  └─ ml_probability: {:.4}", prob);
        }
    }

    for e in &result.engines {
        if let Some(ms) = e.elapsed_ms {
            *engine_totals.entry(e.engine).or_insert(0) += ms;
        }
    }

    if matches!(result.verdict,
        hydradragonav::verdict::Verdict::Malware
        | hydradragonav::verdict::Verdict::Phishing
        | hydradragonav::verdict::Verdict::Suspicious
        | hydradragonav::verdict::Verdict::Pua
    ) {
        harmful_results.push((path.to_path_buf(), result));
    }
}

/// Walk multiple paths with a progress bar, printing threats as they are found.
fn scan_paths(
    paths: &[PathBuf],
    pipeline: &Pipeline,
    json: bool,
    output: Option<&std::path::Path>,
    harmful_results: &mut Vec<(PathBuf, hydradragonav::verdict::ScanResult)>,
    engine_totals: &mut std::collections::HashMap<&'static str, u64>,
    time_engines: bool,
) {
    eprintln!("[Scan] ================================================================================");
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {pos} files scanned | {msg}").unwrap());

    let mut files_scanned = 0u64;
    let mut threats_found = 0u64;
    let scan_start = Instant::now();

    fn walk(
        dir: &std::path::Path,
        pipeline: &Pipeline,
        json: bool,
        files_scanned: &mut u64,
        threats: &mut u64,
        harmful: &mut Vec<(PathBuf, hydradragonav::verdict::ScanResult)>,
        engine_totals: &mut std::collections::HashMap<&'static str, u64>,
        pb: &ProgressBar,
    ) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let meta = match std::fs::metadata(&path) { Ok(m) => m, Err(_) => continue };
                    if meta.len() < 12 { continue; }
                    let result = pipeline.scan_file(&path);
                    *files_scanned += 1;
                    for e in &result.engines {
                        if let Some(ms) = e.elapsed_ms {
                            *engine_totals.entry(e.engine).or_insert(0) += ms;
                        }
                    }
                    pb.set_message(format!("{} threats | {}", threats, path.display()));
                    pb.inc(1);
                    if json {
                        println!("{}", serde_json::to_string(&serde_json::json!({
                            "file": path.to_string_lossy(),
                            "verdict": result.verdict.label(),
                            "threat_name": result.threat_name,
                            "engines": result.engines,
                        })).unwrap());
                    } else if result.verdict.label() != "Clean" && result.verdict.label() != "Trusted" {
                        *threats += 1;
                        let sev = severity_from_verdict(result.verdict);
                        println!("[{}] {}  severity: {}", result.verdict.label(), path.display(), severity_bar(sev));
                        if let Some(ref tn) = result.threat_name {
                            println!("  └─ threat: {}", tn);
                        }
                    }
                    if matches!(result.verdict,
                        hydradragonav::verdict::Verdict::Malware
                        | hydradragonav::verdict::Verdict::Phishing
                        | hydradragonav::verdict::Verdict::Suspicious
                        | hydradragonav::verdict::Verdict::Pua
                    ) { harmful.push((path, result)); }
                } else if path.is_dir() {
                    if pipeline.is_excluded(&path) {
                        pb.set_message(format!("skipping excluded dir: {}", path.display()));
                        continue;
                    }
                    walk(&path, pipeline, json, files_scanned, threats, harmful, engine_totals, pb);
                }
            }
        }
    }

    for p in paths {
        if p.is_dir() {
            walk(p, pipeline, json, &mut files_scanned, &mut threats_found, harmful_results, engine_totals, &pb);
        } else {
            let meta = match std::fs::metadata(p) { Ok(m) => m, Err(_) => continue };
            if meta.len() < 12 { continue; }
            let result = pipeline.scan_file(p);
            files_scanned += 1;
            for e in &result.engines {
                if let Some(ms) = e.elapsed_ms {
                    *engine_totals.entry(e.engine).or_insert(0) += ms;
                }
            }
            pb.set_message(format!("{} threats | {}", threats_found, p.display()));
            pb.inc(1);
            if json {
                println!("{}", serde_json::to_string(&serde_json::json!({
                    "file": p.to_string_lossy(),
                    "verdict": result.verdict.label(),
                    "threat_name": result.threat_name,
                    "engines": result.engines,
                })).unwrap());
            } else if result.verdict.label() != "Clean" && result.verdict.label() != "Trusted" {
                threats_found += 1;
                let sev = severity_from_verdict(result.verdict);
                println!("[{}] {}  severity: {}", result.verdict.label(), p.display(), severity_bar(sev));
                if let Some(ref tn) = result.threat_name {
                    println!("  └─ threat: {}", tn);
                }
            }
            if matches!(result.verdict,
                hydradragonav::verdict::Verdict::Malware
                | hydradragonav::verdict::Verdict::Phishing
                | hydradragonav::verdict::Verdict::Suspicious
                | hydradragonav::verdict::Verdict::Pua
            ) { harmful_results.push((p.to_path_buf(), result)); }
        }
    }

    let elapsed = scan_start.elapsed();
    pb.finish_and_clear();

    if let Some(output_path) = output {
        let entries: Vec<serde_json::Value> = harmful_results.iter().map(|(p, r)| {
            serde_json::json!({"file": p.to_string_lossy(), "verdict": r.verdict.label(), "threat_name": r.threat_name, "engines": r.engines})
        }).collect();
        if let Err(e) = std::fs::write(output_path, serde_json::to_string_pretty(&serde_json::json!({
            "scan_root": paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
            "files_scanned": files_scanned, "threats_found": threats_found, "results": entries,
        })).unwrap()) {
            eprintln!("[Scan] Failed to write report to {}: {}", output_path.display(), e);
        } else { eprintln!("[Scan] Malware report written to {}", output_path.display()); }
    }

    let secs = elapsed.as_secs_f64();
    eprintln!("[Scan] ================================================================================");
    eprintln!("[Scan] Scan Complete!");
    eprintln!("[Scan] Total files scanned: {}", files_scanned);
    eprintln!("[Scan] Total threats found: {}", threats_found);
    eprintln!("[Scan] Time elapsed:         {:.2?}", elapsed);
    eprintln!("[Scan] Scan rate:            {:.1} files/sec", files_scanned as f64 / secs);

    if time_engines && !engine_totals.is_empty() {
        let mut rows: Vec<(&str, u64)> = engine_totals.drain().collect();
        rows.sort_by_key(|&(_, ms)| std::cmp::Reverse(ms));
        eprintln!("[Scan] Per-engine totals (slowest first):");
        for (engine, ms) in rows { eprintln!("[Scan]   {:<20} {:>10} ms", engine, ms); }
    }
}

fn main() {
    let cli = Cli::parse();
    let (db, blm, yara, hydradragonsig_rules, hayabusa, pe_ml, js_ml, reglist) = default_paths();

    let config = FullConfig {
        db: cli.db.unwrap_or(db),
        bloom_dir: cli.bloom_dir.or(Some(blm)),
        yara_dir: cli.yara_dir.or(Some(yara)),
        hydradragonsig_rules_dir: cli
            .hydradragonsig_rules_dir
            .or(Some(hydradragonsig_rules)),
        hayabusa_dir: cli.hayabusa_dir.or(Some(hayabusa)),
        pe_ml_model: cli.pe_ml_model.or(Some(pe_ml)),
        js_ml_model: cli.js_ml_model.or(Some(js_ml)),
        reglist: Some(reglist),
        ml_threshold: cli.ml_threshold,
    };

    match &cli.command {
        Command::Scan {
            paths,
            files,
            memory,
            registry,
            sigma,
            pum,
            json,
            output,
            time_engines,
            fast_scan,
        } => {
            let mut cats = Vec::new();
            if *files { cats.push(ScanCategory::Files); }
            if *memory { cats.push(ScanCategory::Memory); }
            if *registry { cats.push(ScanCategory::Registry); }
            if *sigma { cats.push(ScanCategory::Sigma); }
            if *pum { cats.push(ScanCategory::Pum); }
            cmd_custom_scan(paths, cats, *json, output.as_deref(), *time_engines, *fast_scan, &config)
        }
        Command::Update => match config.hayabusa_dir.as_deref() {
            Some(hdir) => cmd_update_hayabusa(hdir),
            None => eprintln!("[Hayabusa] hayabusa_dir not configured, skipping."),
        },
        Command::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        Command::Quarantine { action } => cmd_quarantine(action, &config.db),
        Command::DisinfectPending => {
            let dir = config
                .db
                .parent()
                .map(|p| p.join("quarantine"))
                .unwrap_or_else(|| PathBuf::from("quarantine"));
            for line in hydradragonav::restart_disinfect::run_pending_disinfection(&dir) {
                println!("[Disinfect/boot] {line}");
            }
        }
    }
}

fn cmd_quarantine(action: &QuarantineAction, db_path: &std::path::Path) {
    let dir = db_path
        .parent()
        .map(|p| p.join("quarantine"))
        .unwrap_or_else(|| PathBuf::from("quarantine"));
    let q = hydradragonav::quarantine::Quarantine::new(&dir);
    match action {
        QuarantineAction::List => {
            let items = q.list();
            if items.is_empty() {
                println!("No quarantined files. (store: {})", dir.join("store").display());
                return;
            }
            println!("{} quarantined file(s):", items.len());
            for e in items {
                println!(
                    "  {}\n    original : {}\n    detection: {}   size: {} bytes   sha256: {}",
                    e.id,
                    e.original_path.display(),
                    e.detection,
                    e.size,
                    e.sha256
                );
            }
        }
        QuarantineAction::Restore { id } => match q.restore(id) {
            Ok(p) => println!("Restored {id} -> {}", p.display()),
            Err(e) => {
                eprintln!("Restore failed for {id}: {e}");
                std::process::exit(1);
            }
        },
        QuarantineAction::Delete { id } => match q.delete(id) {
            Ok(()) => println!("Permanently deleted {id}"),
            Err(e) => {
                eprintln!("Delete failed for {id}: {e}");
                std::process::exit(1);
            }
        },
    }
}

/// After a scan, interactively offer to clean each infected file. Disinfection
/// neutralizes the matched signature arenas in place (keeping a `.bak`); files
/// with no recoverable arena — or where neutralization fails — are quarantined.
fn offer_disinfection(
    infected: &[(PathBuf, Option<String>)],
    pipeline: &Pipeline,
    db_path: &std::path::Path,
) {
    use std::io::Write;

    if infected.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("[Disinfect] {} infected file(s) detected.", infected.len());
    eprintln!("[Disinfect] Disinfection neutralizes matched signature regions in place (a .bak");
    eprintln!("[Disinfect] backup is kept) but may miss other malicious parts — deleting the file");
    eprintln!("[Disinfect] is safer. Files with no recoverable signature arena are quarantined.");

    let quarantine_dir = db_path
        .parent()
        .map(|p| p.join("quarantine"))
        .unwrap_or_else(|| PathBuf::from("quarantine"));

    let stdin = std::io::stdin();
    for (path, threat) in infected {
        let label = threat.as_deref().unwrap_or("malware");
        eprint!(
            "[Disinfect] Clean '{}' ({})? [d=disinfect/quarantine, s=skip, q=quit]: ",
            path.display(),
            label
        );
        let _ = std::io::stderr().flush();

        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            eprintln!("\n[Disinfect] no input available; aborting disinfection.");
            return;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "q" | "quit" => {
                eprintln!("[Disinfect] aborted.");
                return;
            }
            "d" | "disinfect" | "y" | "yes" => {
                // Recover ClamAV + YARA-X matched arenas (file offsets).
                let arenas = pipeline.arenas_for_file(path);
                match disinfector::disinfect_file(path, &arenas, &quarantine_dir) {
                    DisinfectOutcome::Neutralized { bytes, backup } => eprintln!(
                        "[Disinfect] neutralized {bytes} byte(s) in {}; backup at {}",
                        path.display(),
                        backup.display()
                    ),
                    DisinfectOutcome::Quarantined { to } => eprintln!(
                        "[Disinfect] no signature arena; quarantined to {}",
                        to.display()
                    ),
                    DisinfectOutcome::Failed { reason } => {
                        eprintln!("[Disinfect] FAILED for {}: {reason}", path.display());
                        // Escalate: the file is likely locked by a running (possibly
                        // self-critical) process. Kill it (clearing the critical flag
                        // if needed), retry; if still stuck, defer to next boot via a
                        // RunOnce + marker. CLI does not force a reboot.
                        use hydradragonav::restart_disinfect::{escalated_disinfect, EscalationOutcome};
                        match escalated_disinfect(path, &quarantine_dir, label, false) {
                            EscalationOutcome::Quarantined => {
                                eprintln!("[Disinfect] escalation quarantined {}", path.display())
                            }
                            EscalationOutcome::KilledAndQuarantined(n) => eprintln!(
                                "[Disinfect] killed {n} blocking process(es), quarantined {}",
                                path.display()
                            ),
                            EscalationOutcome::ScheduledForRestart { detail, .. } => eprintln!(
                                "[Disinfect] could not clean live; {detail}. Restart to finish (run `hydradragonav disinfect-pending` after reboot, or it runs automatically via RunOnce)."
                            ),
                            EscalationOutcome::Failed(e) => {
                                eprintln!("[Disinfect] escalation failed for {}: {e}", path.display())
                            }
                        }
                    }
                }
                // After cleaning the file, hunt down and remove its traces.
                offer_trace_removal(path, &quarantine_dir, &stdin);
            }
            _ => eprintln!("[Disinfect] skipped {}", path.display()),
        }
    }
}

/// Find a malicious file's traces (autorun registry, services, scheduled tasks,
/// prefetch, startup shortcuts, uninstall entries) and offer to remove them.
fn offer_trace_removal(
    path: &std::path::Path,
    quarantine_dir: &std::path::Path,
    stdin: &std::io::Stdin,
) {
    use std::io::Write;

    let traces = remediation::find_traces(path);
    if traces.is_empty() {
        eprintln!(
            "[Remediate] no registry/service/task/prefetch/startup traces found for {}",
            path.display()
        );
        return;
    }

    eprintln!(
        "[Remediate] {} trace(s) found for {}:",
        traces.len(),
        path.display()
    );
    for t in &traces {
        eprintln!("  [{}] {}", t.category, t.description);
    }
    eprint!("[Remediate] Remove these traces? [a=remove all, s=skip] (admin rights needed): ");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    if stdin.read_line(&mut line).unwrap_or(0) == 0 {
        eprintln!("\n[Remediate] no input; skipping trace removal.");
        return;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "a" | "all" | "y" | "yes" => {
            eprintln!("[Remediate] creating a Windows System Restore Point before changes...");
            match remediation::create_restore_point("HydraDragon malware remediation") {
                Ok(_) => eprintln!("[Remediate] System Restore Point created."),
                Err(e) => eprintln!(
                    "[Remediate] WARNING: restore point not created ({e}); per-key .reg backups are still saved before each registry deletion."
                ),
            }
            for t in &traces {
                match remediation::apply(t, quarantine_dir) {
                    Ok(msg) => eprintln!("[Remediate] {msg}"),
                    Err(e) => {
                        eprintln!("[Remediate] FAILED [{}] {}: {e}", t.category, t.description)
                    }
                }
            }
        }
        _ => eprintln!("[Remediate] skipped trace removal."),
    }
}

fn cmd_update_hayabusa(hayabusa_dir: &std::path::Path) {
    let exe = hayabusa_dir.join("hayabusa-3.9.0-win-x64.exe");
    if !exe.exists() {
        eprintln!("[Hayabusa] executable not found at {}", exe.display());
        return;
    }
    eprintln!("[Hayabusa] Updating rules...");
    match std::process::Command::new(&exe)
        .args(["update-rules", "--quiet"])
        .current_dir(hayabusa_dir)
        .status()
    {
        Ok(s) if s.success() => eprintln!("[Hayabusa] Rules updated successfully."),
        Ok(s) => eprintln!("[Hayabusa] update-rules exited with: {}", s),
        Err(e) => eprintln!("[Hayabusa] Failed to run update-rules: {}", e),
    }
}

fn print_memory_scan(detections: &[hydradragonav::memory_scanner::MemoryDetection]) {
    println!("[Memory Scan]");
    if detections.is_empty() {
        println!("  No threats detected in process memory.");
        return;
    }
    for d in detections {
        println!(
            "  [{}] {} (pid {}) @ 0x{:x} ({} bytes): {}",
            d.verdict.label(),
            d.process,
            d.pid,
            d.address,
            d.region_size,
            d.threat_name
        );
    }
}

fn scan_registry(config: &FullConfig) -> hydradragonav::registry_scanner::RegistryScanResult {
    let reglist_path = config.reglist.as_deref().filter(|p| p.exists());
    let rules_dir = config
        .hydradragonsig_rules_dir
        .as_deref()
        .filter(|p| p.exists());
    match reglist_path {
        Some(rp) => RegistryScanner::load(rp, rules_dir),
        None => RegistryScanner::default(),
    }
    .scan()
}

fn print_registry_scan(result: &hydradragonav::registry_scanner::RegistryScanResult) {
    println!("[Registry Scan]");
    println!("  Total entries scanned: {}", result.total_scanned);
    println!("  Threats found: {}", result.threats_found);
    for entry in &result.entries {
        if entry.pua_match || entry.static_match {
            let tag = if entry.pua_match && entry.static_match {
                "PUA+STATIC"
            } else if entry.pua_match {
                "PUA"
            } else {
                "STATIC"
            };
            println!(
                "  [{}] {}\\{} (value: {})",
                tag, entry.hive, entry.path, entry.value_name
            );
            if let Some(ref tn) = entry.threat_name {
                println!("    threat: {}", tn);
            }
            if !entry.value_data.is_empty() {
                println!("    data: {}", entry.value_data);
            }
            println!("    detail: {}", entry.detail);
        }
    }
    if result.threats_found == 0 {
        println!("  No threats detected.");
    }
}
