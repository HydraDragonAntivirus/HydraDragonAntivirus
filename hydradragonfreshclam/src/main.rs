#![cfg(windows)]

mod clamjuice;
mod error;
mod ffi;
mod freshclam;

use std::path::PathBuf;

use clap::Parser;

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Parser)]
#[command(
    name = "hydradragonfreshclam",
    version,
    about = "Update ClamAV databases via libfreshclam.dll, then filter them with ClamJuice (all platforms, no hash signatures)"
)]
struct Cli {
    /// Path to libfreshclam.dll
    #[arg(long, env = "FRESHCLAM_DLL_PATH")]
    freshclam: Option<PathBuf>,

    /// ClamAV database directory to update and filter
    #[arg(long, env = "CLAMAV_DATABASE")]
    db: Option<PathBuf>,

    /// Certificates directory (defaults to <freshclam_dir>/certs)
    #[arg(long, env = "CLAMAV_CERTS")]
    certs: Option<PathBuf>,

    /// Keep the original .cvd/.cld files after filtering (default: delete them)
    #[arg(long)]
    keep_source: bool,

    /// Download only; skip the ClamJuice filtering step
    #[arg(long)]
    no_juice: bool,

    /// Skip the download; only run ClamJuice on the existing databases
    #[arg(long)]
    juice_only: bool,
}

fn main() {
    let cli = Cli::parse();

    let freshclam = cli
        .freshclam
        .unwrap_or_else(|| exe_dir().join("libfreshclam.dll"));
    let db = cli.db.unwrap_or_else(|| exe_dir().join("database"));
    let certs = cli
        .certs
        .or_else(|| freshclam.parent().map(|p| p.join("certs")));

    if !cli.juice_only {
        eprintln!("[ClamAV] Updating databases via libfreshclam.dll...");
        match freshclam::run_freshclam_dll(&freshclam, &db, certs.as_deref()) {
            Ok(()) => eprintln!("[ClamAV] Database update completed successfully."),
            Err(e) => {
                eprintln!("[ClamAV] Database update failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if !cli.no_juice {
        eprintln!("[ClamJuice] Filtering databases (all platforms, no hash signatures)...");
        clamjuice::run_juice(&db, !cli.keep_source);
    }
}
