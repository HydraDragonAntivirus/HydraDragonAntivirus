#![cfg(windows)]

use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use hydradragonav::disinfector::{self, DisinfectOutcome};
use hydradragonav::remediation;
use hydradragonav::memory_scanner;
use hydradragonav::pipeline::scan_hayabusa_once;
use hydradragonav::pipeline::{Pipeline, PipelineConfig, ScanMode};
use hydradragonav::registry_scanner::RegistryScanner;

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
    /// Scan a file or directory through the detection pipeline
    Scan {
        /// File or directory to scan
        path: PathBuf,

        /// Scan mode: full (files + memory + registry + logs), files-only, or non-files (registry + logs).
        /// "memory" = running-process RAM (run elevated to reach protected processes); "logs" = Hayabusa event logs.
        #[arg(long, short, default_value = "files-only")]
        mode: ScanMode,

        /// Output raw JSON (default: human-readable)
        #[arg(long, short)]
        json: bool,

        /// Write malware-only results to this file after directory scan
        #[arg(long)]
        output: Option<PathBuf>,

        /// Accepted for compatibility; the pure-Rust ClamAV engine has no separate heuristic mode
        #[arg(long)]
        heuristics: bool,

        /// Print per-engine timing and highlight the slowest engine
        #[arg(long)]
        time_engines: bool,

        /// Enable yara-x fast-scan mode (stops tracking matches after first match for boolean-only patterns)
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

fn cmd_scan(
    path: &std::path::Path,
    mode: ScanMode,
    json: bool,
    output: Option<&std::path::Path>,
    heuristics: bool,
    time_engines: bool,
    fast_scan: bool,
    config: &FullConfig,
) {
    match mode {
        ScanMode::NonFiles => cmd_scan_metadata(json, config),
        _ => {
            if path.is_dir() {
                cmd_scan_recursive(
                    path,
                    mode,
                    json,
                    output,
                    heuristics,
                    time_engines,
                    fast_scan,
                    config,
                );
            } else {
                cmd_scan_single(
                    path,
                    mode,
                    json,
                    heuristics,
                    time_engines,
                    fast_scan,
                    config,
                );
            }
        }
    }
}

fn cmd_scan_metadata(json: bool, config: &FullConfig) {
    // Non-files mode = memory + registry + logs. The memory scan needs the engine,
    // so build the pipeline here too (no file scanning happens).
    let pipeline = Pipeline::new(PipelineConfig {
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
        scan_mode: ScanMode::NonFiles,
        ml_threshold: config.ml_threshold,
        ..Default::default()
    });

    if json {
        let mut output = serde_json::json!({});
        let reg_result = scan_registry(config);
        output["registry_scan"] = serde_json::to_value(&reg_result).unwrap();
        if let Some(ref hdir) = config.hayabusa_dir {
            let hayabusa_matches = scan_hayabusa_once(hdir);
            output["hayabusa_matches"] = serde_json::to_value(&hayabusa_matches).unwrap();
        }
        output["memory_scan"] =
            serde_json::to_value(memory_scanner::scan_process_memory(&pipeline)).unwrap();
        println!("{}", serde_json::to_string(&output).unwrap());
    } else {
        println!("[Metadata Scan]");
        print_registry_scan(&scan_registry(config));
        if let Some(ref hdir) = config.hayabusa_dir {
            let hayabusa_matches = scan_hayabusa_once(hdir);
            if !hayabusa_matches.is_empty() {
                println!("[Hayabusa]");
                for m in &hayabusa_matches {
                    println!("  ├─ {m}");
                }
            }
        }
        print_memory_scan(&memory_scanner::scan_process_memory(&pipeline));
    }
}

fn cmd_scan_single(
    path: &std::path::Path,
    mode: ScanMode,
    json: bool,
    heuristics: bool,
    time_engines: bool,
    fast_scan: bool,
    config: &FullConfig,
) {
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
        scan_mode: mode,
        clamav_heuristics: heuristics,
        time_engines,
        fast_scan,
        ml_threshold: config.ml_threshold,
        ..Default::default()
    };

    let pipeline = Pipeline::new(pipeline_config);
    let scan_start = Instant::now();
    let result = pipeline.scan_file(path);
    let elapsed = scan_start.elapsed();

    if json {
        let mut output = serde_json::json!({
            "file": path.to_string_lossy(),
            "verdict": result.verdict.label(),
            "threat_name": result.threat_name,
            "engines": result.engines,
            "scan_time_ms": elapsed.as_millis(),
        });
        if matches!(mode, ScanMode::Full | ScanMode::NonFiles) {
            let reg_result = scan_registry(config);
            output["registry_scan"] = serde_json::to_value(&reg_result).unwrap();
            if let Some(ref hdir) = config.hayabusa_dir {
                let hayabusa_matches = scan_hayabusa_once(hdir);
                output["hayabusa_matches"] = serde_json::to_value(&hayabusa_matches).unwrap();
            }
            output["memory_scan"] =
                serde_json::to_value(memory_scanner::scan_process_memory(&pipeline)).unwrap();
        }
        println!("{}", serde_json::to_string(&output).unwrap());
    } else {
        println!(
            "[{}] {} ({:.0?})",
            result.verdict.label(),
            path.display(),
            elapsed
        );
        if let Some(ref tn) = result.threat_name {
            println!("  threat: {}", tn);
        }
        let slowest = result
            .engines
            .iter()
            .filter_map(|e| e.elapsed_ms.map(|ms| (e.engine, ms)))
            .max_by_key(|&(_, ms)| ms);
        for e in &result.engines {
            match e.elapsed_ms {
                Some(ms) => {
                    let mark = if slowest.map(|(name, _)| name == e.engine).unwrap_or(false) {
                        "  <-- slowest"
                    } else {
                        ""
                    };
                    println!(
                        "  ├─ {}: {} ({}) [{} ms]{}",
                        e.engine,
                        e.verdict.label(),
                        e.detail,
                        ms,
                        mark
                    );
                }
                None => println!("  ├─ {}: {} ({})", e.engine, e.verdict.label(), e.detail),
            }
        }
        if let Some(prob) = result.ml_malware_probability {
            println!("  └─ ml_probability: {:.4}", prob);
        }
        if matches!(mode, ScanMode::Full | ScanMode::NonFiles) {
            print_registry_scan(&scan_registry(config));
            if let Some(ref hdir) = config.hayabusa_dir {
                let hayabusa_matches = scan_hayabusa_once(hdir);
                if !hayabusa_matches.is_empty() {
                    println!("[Hayabusa]");
                    for m in &hayabusa_matches {
                        println!("  ├─ {m}");
                    }
                }
            }
            print_memory_scan(&memory_scanner::scan_process_memory(&pipeline));
        }
    }

    if !json
        && matches!(
            result.verdict,
            hydradragonav::verdict::Verdict::Malware
                | hydradragonav::verdict::Verdict::Abuse
                | hydradragonav::verdict::Verdict::Phishing
                | hydradragonav::verdict::Verdict::Suspicious
                | hydradragonav::verdict::Verdict::Spam
                | hydradragonav::verdict::Verdict::Mining
                | hydradragonav::verdict::Verdict::Pua
        )
    {
        let infected = vec![(path.to_path_buf(), result.threat_name.clone())];
        offer_disinfection(&infected, &pipeline, &config.db);
    }
}

fn cmd_scan_recursive(
    root_path: &std::path::Path,
    mode: ScanMode,
    json: bool,
    output: Option<&std::path::Path>,
    heuristics: bool,
    time_engines: bool,
    fast_scan: bool,
    config: &FullConfig,
) {
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
        scan_mode: mode,
        clamav_heuristics: heuristics,
        time_engines,
        fast_scan,
        ml_threshold: config.ml_threshold,
        ..Default::default()
    };

    let pipeline = Pipeline::new(pipeline_config);

    eprintln!(
        "[Scan] ================================================================================"
    );

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] {pos} files scanned | {msg}",
        )
        .unwrap(),
    );

    let mut files_scanned = 0u64;
    let mut threats_found = 0u64;
    let mut harmful_results: Vec<(std::path::PathBuf, hydradragonav::verdict::ScanResult)> =
        Vec::new();
    let mut engine_totals: std::collections::HashMap<&'static str, u64> =
        std::collections::HashMap::new();

    fn walk_and_scan(
        dir: &std::path::Path,
        pipeline: &Pipeline,
        mode: ScanMode,
        json: bool,
        files_scanned: &mut u64,
        threats_found: &mut u64,
        harmful_results: &mut Vec<(std::path::PathBuf, hydradragonav::verdict::ScanResult)>,
        engine_totals: &mut std::collections::HashMap<&'static str, u64>,
        pb: &ProgressBar,
    ) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let meta = match std::fs::metadata(&path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if meta.len() < 12 {
                        continue;
                    }
                    let result = pipeline.scan_file(&path);
                    *files_scanned += 1;
                    for e in &result.engines {
                        if let Some(ms) = e.elapsed_ms {
                            *engine_totals.entry(e.engine).or_insert(0) += ms;
                        }
                    }
                    pb.set_message(format!("{} threats | {}", threats_found, path.display()));
                    pb.inc(1);

                    if json {
                        let output = serde_json::json!({
                            "file": path.to_string_lossy(),
                            "verdict": result.verdict.label(),
                            "threat_name": result.threat_name,
                            "engines": result.engines,
                        });
                        println!("{}", serde_json::to_string(&output).unwrap());
                    } else {
                        if result.verdict.label() != "Clean" && result.verdict.label() != "Trusted"
                        {
                            *threats_found += 1;
                            println!("[{}] {}", result.verdict.label(), path.display());
                            if let Some(ref tn) = result.threat_name {
                                println!("  └─ threat: {}", tn);
                            }
                        }
                    }

                    if matches!(
                        result.verdict,
                        hydradragonav::verdict::Verdict::Malware
                            | hydradragonav::verdict::Verdict::Abuse
                            | hydradragonav::verdict::Verdict::Phishing
                            | hydradragonav::verdict::Verdict::Suspicious
                            | hydradragonav::verdict::Verdict::Spam
                            | hydradragonav::verdict::Verdict::Mining
                            | hydradragonav::verdict::Verdict::Pua
                    ) {
                        harmful_results.push((path, result));
                    }
                } else if path.is_dir() {
                    walk_and_scan(
                        &path,
                        pipeline,
                        mode,
                        json,
                        files_scanned,
                        threats_found,
                        harmful_results,
                        engine_totals,
                        pb,
                    );
                }
            }
        }
    }

    let scan_start = Instant::now();
    walk_and_scan(
        root_path,
        &pipeline,
        mode,
        json,
        &mut files_scanned,
        &mut threats_found,
        &mut harmful_results,
        &mut engine_totals,
        &pb,
    );
    let elapsed = scan_start.elapsed();
    pb.finish_and_clear();

    if let Some(output_path) = output {
        let entries: Vec<serde_json::Value> = harmful_results
            .iter()
            .map(|(path, result)| {
                serde_json::json!({
                    "file": path.to_string_lossy(),
                    "verdict": result.verdict.label(),
                    "threat_name": result.threat_name,
                    "engines": result.engines,
                })
            })
            .collect();
        let report = serde_json::json!({
            "scan_root": root_path.to_string_lossy(),
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "results": entries,
        });
        if let Err(e) = std::fs::write(output_path, serde_json::to_string_pretty(&report).unwrap())
        {
            eprintln!(
                "[Scan] Failed to write report to {}: {}",
                output_path.display(),
                e
            );
        } else {
            eprintln!("[Scan] Malware report written to {}", output_path.display());
        }
    }

    let secs = elapsed.as_secs_f64();
    let rate = if secs > 0.0 {
        files_scanned as f64 / secs
    } else {
        0.0
    };

    eprintln!(
        "[Scan] ================================================================================"
    );
    eprintln!("[Scan] Scan Complete!");
    eprintln!("[Scan] Total files scanned: {}", files_scanned);
    eprintln!("[Scan] Total threats found: {}", threats_found);
    eprintln!("[Scan] Time elapsed:         {:.2?}", elapsed);
    eprintln!("[Scan] Scan rate:            {:.1} files/sec", rate);

    if time_engines && !engine_totals.is_empty() {
        let mut rows: Vec<(&'static str, u64)> = engine_totals.into_iter().collect();
        rows.sort_by_key(|&(_, ms)| std::cmp::Reverse(ms));
        eprintln!("[Scan] Per-engine totals (slowest first):");
        for (engine, ms) in rows {
            eprintln!("[Scan]   {:<20} {:>10} ms", engine, ms);
        }
    }

    if !json && !harmful_results.is_empty() {
        let infected: Vec<(PathBuf, Option<String>)> = harmful_results
            .iter()
            .map(|(path, result)| (path.clone(), result.threat_name.clone()))
            .collect();
        offer_disinfection(&infected, &pipeline, &config.db);
    }

    if matches!(mode, ScanMode::Full | ScanMode::NonFiles) {
        eprintln!();
        if json {
            let reg_result = scan_registry(config);
            println!("{}", serde_json::to_string(&reg_result).unwrap());
            if let Some(ref hdir) = config.hayabusa_dir {
                let hayabusa_matches = scan_hayabusa_once(hdir);
                println!("{}", serde_json::to_string(&hayabusa_matches).unwrap());
            }
            println!(
                "{}",
                serde_json::to_string(&memory_scanner::scan_process_memory(&pipeline)).unwrap()
            );
        } else {
            print_registry_scan(&scan_registry(config));
            if let Some(ref hdir) = config.hayabusa_dir {
                let hayabusa_matches = scan_hayabusa_once(hdir);
                if !hayabusa_matches.is_empty() {
                    println!("[Hayabusa]");
                    for m in &hayabusa_matches {
                        println!("  ├─ {m}");
                    }
                }
            }
            print_memory_scan(&memory_scanner::scan_process_memory(&pipeline));
        }
    }
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
            path,
            mode,
            json,
            output,
            heuristics,
            time_engines,
            fast_scan,
        } => cmd_scan(
            path,
            *mode,
            *json,
            output.as_deref(),
            *heuristics,
            *time_engines,
            *fast_scan,
            &config,
        ),
        Command::Update => match config.hayabusa_dir.as_deref() {
            Some(hdir) => cmd_update_hayabusa(hdir),
            None => eprintln!("[Hayabusa] hayabusa_dir not configured, skipping."),
        },
        Command::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        Command::Quarantine { action } => cmd_quarantine(action, &config.db),
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
                        eprintln!("[Disinfect] FAILED for {}: {reason}", path.display())
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
