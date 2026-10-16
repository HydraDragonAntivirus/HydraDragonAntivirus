mod budget;
mod cache;
mod config;
mod dashboard;
mod dataset;
mod disinfect;
mod disasm;
mod engine_adapter;
mod apk;
mod fingerprint;
mod analyst_engine;
mod analyzer;
mod alyzer;
mod archive;
mod human_review;
mod ip_bans;
mod naming;
mod reports;
mod folder_wl;
mod fp_ignore;
mod offload;
mod rescan;
mod retrohunt;
mod sample_zip;
mod similarity;
mod events;
mod handoff;
mod limits;
mod liveness;
mod ratelimit;
mod scan_server;
mod scheduler;
mod threat_intel;
mod uptime;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use config::{app_dir, CliArgs};
use dashboard::{dashboard_router, AppState};
use engine_adapter::EngineAdapter;
use events::EventLog;
use scan_server::ScanServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = CliArgs::parse();
    args.enforce_limits();
    args.archive = args.archive || config::archive_in_settings();
    config::set_archive(args.archive);
    let ui_addr: SocketAddr = args
        .ui
        .parse()
        .map_err(|e| format!("invalid --ui address '{}': {}", args.ui, e))?;
    // The dashboard can give human verdicts and change the server: this computer only.
    if !ui_addr.ip().is_loopback() {
        return Err(format!(
            "--ui {ui_addr}: the dashboard only listens on this computer (127.0.0.1 or [::1]), not on the network"
        )
        .into());
    }

    // Seamless update (`--handoff`, started by Multron Updater next to the running
    // server): load everything while the running server keeps scanning, then take over.
    let mut handoff_from: Option<u32> = None;
    if args.handoff {
        match handoff::begin(ui_addr).await {
            handoff::Begin::Accepted { pid } => {
                eprintln!("[handoff] standby: the running server (pid {pid}) keeps scanning while this version loads");
                config::set_standby(true);
                handoff_from = Some(pid);
            }
            handoff::Begin::NoServer => eprintln!("[handoff] no server is running on {ui_addr}: normal start"),
            handoff::Begin::Unsupported => {
                eprintln!("[handoff] the running server does not support seamless updates; exiting (the updater restarts it the usual way)");
                std::process::exit(handoff::EXIT_UNSUPPORTED);
            }
        }
    }
    let standby = handoff_from.is_some();
    if !standby {
        uptime::start();
    }
    if args.archive {
        eprintln!("[archive] read-only archive server: data comes from the main server's mirror in {}", app_dir().display());
    }

    let events = Arc::new(EventLog::new(args.verbose));

    let work_dir = if args.memory_only {
        None
    } else if args.work_dir.is_empty() {
        Some(app_dir().join("multron_incoming"))
    } else {
        Some(PathBuf::from(&args.work_dir))
    };

    let engine = EngineAdapter::new(
        work_dir,
        !args.no_hash_whitelist,
        !args.no_keep_unknown,
        args.keep_unknown_gb,
        args.keep_threats(),
        args.keep_clean,
        args.keep_clean_gb,
        args.compress_low_disk_flag().unwrap_or(false),
        args.low_disk_gb,
    );
    let custom_rules = if args.rules.is_empty() {
        None
    } else {
        Some(PathBuf::from(&args.rules))
    };
    // The archive serves stored data only and never scans: no rules, no models, no RAM for them.
    if !args.archive {
        engine.start_loading(custom_rules);
    }

    let lengths = standby.then(handoff::lengths);
    let threat_intel = threat_intel::ThreatIntelStore::new(None);

    // Standby: wait for the engine (calling the running server every few seconds and
    // following what it writes), then ask it to hand over and take its ports.
    let mut early_dashboard: Option<tokio::net::TcpListener> = None;
    let mut old_listening = false;
    let mut switch_started: Option<std::time::Instant> = None;
    if let (Some(old_pid), Some(lengths)) = (handoff_from, lengths) {
        let mut follow = handoff::Follow::new(lengths);
        let mut last_beat = std::time::Instant::now();
        let waited = std::time::Instant::now();
        while !args.archive && !engine.is_ready().await {
            if engine.load_failed() {
                eprintln!("[handoff] the engine failed to load; the running server stays (update cancelled)");
                handoff::cancel(ui_addr).await;
                std::process::exit(1);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            if last_beat.elapsed() >= handoff::BEAT_EVERY {
                last_beat = std::time::Instant::now();
                if let handoff::Begin::NoServer = handoff::begin(ui_addr).await {
                    eprintln!("[handoff] the running server is gone; taking over when the engine is ready");
                }
                tokio::task::block_in_place(|| follow.catch_up(&threat_intel));
            }
        }
        eprintln!("[handoff] ready after {} s; asking pid {old_pid} to hand over", waited.elapsed().as_secs());
        let switch = std::time::Instant::now();
        switch_started = Some(switch);
        match handoff::release(ui_addr, args.handoff_drain_secs).await {
            Ok(r) => old_listening = r.listening,
            Err(e) if e.starts_with("release refused") => {
                eprintln!("[handoff] {e}; the running server stays (update cancelled)");
                handoff::cancel(ui_addr).await;
                std::process::exit(1);
            }
            // No answer (it may be gone already): the free port decides.
            Err(e) => {
                eprintln!("[handoff] release: {e}; waiting for the port");
                old_listening = true;
            }
        }
        match handoff::bind_when_free(ui_addr, Duration::from_secs(60)).await {
            Ok(l) => early_dashboard = Some(l),
            Err(e) => {
                eprintln!("[handoff] {e}; exiting");
                std::process::exit(1);
            }
        }
        // The old process has exited: everything it wrote is on disk now.
        config::set_standby(false);
        let lines = tokio::task::block_in_place(|| follow.catch_up(&threat_intel));
        engine.after_takeover();
        uptime::start();
        eprintln!("[handoff] took over from pid {old_pid} ({lines} new lines read, {} ms since the hand-over started)", switch.elapsed().as_millis());
    }

    if standby && !args.archive {
        // Upkeep the old server already did at its start: in the background, so the
        // listener comes up at once. Analyst signatures may have changed meanwhile.
        let ti = Arc::clone(&threat_intel);
        let eng = Arc::clone(&engine);
        let _ = std::thread::Builder::new().name("handoff-upkeep".into()).spawn(move || {
            eng.analyst.reload();
            startup_upkeep(&eng, &ti);
        });
    } else if !args.archive {
        startup_upkeep(&engine, &threat_intel);
    }
    let scan_server = ScanServer::new(
        args.clone(),
        Arc::clone(&engine),
        Arc::clone(&events),
        Arc::clone(&threat_intel),
    );
    if args.archive {
        crate::archive::spawn_reloader(Arc::clone(&scan_server));
    } else {
        let srv = Arc::clone(&scan_server);
        crate::offload::spawn_watcher(Arc::clone(&engine), Arc::clone(&scan_server.offload), move |m| srv.log_info(m));
        let srv = Arc::clone(&scan_server);
        scan_server.mirror.set_work_dir(engine.work_dir().map(|p| p.to_path_buf()));
        let ti = Arc::clone(&threat_intel);
        scan_server.mirror.set_verdict_lookup(Arc::new(move |sha: &str| {
            let (verdict, source, _) = ti.effective(&sha.to_ascii_lowercase());
            (source != "unseen").then_some(verdict)
        }));
        scan_server.mirror.spawn(move |m| srv.log_info(m));
    }
    let app_state = AppState::new(
        args.clone(),
        Arc::clone(&engine),
        Arc::clone(&events),
        Arc::clone(&scan_server),
        Arc::clone(&threat_intel),
    )
    .await;
    dashboard::spawn_handoff_watchdog(Arc::clone(&app_state));

    // Seamless update: the old server's scan listener was up, so this one starts now
    // (the port was freed with the old process; retried briefly in case it lingers).
    if standby {
        let settings = app_state.settings.read().await.clone();
        if old_listening || settings.autostart {
            let started = std::time::Instant::now();
            loop {
                match app_state.start_listener(settings.clone()).await {
                    Ok(()) => {
                        let ms = switch_started.map_or(0, |t| t.elapsed().as_millis());
                        eprintln!("[handoff] scanning on {}:{} again, {ms} ms after the hand-over started", settings.host, settings.port);
                        break;
                    }
                    Err(e) if started.elapsed() < Duration::from_secs(15) => {
                        let _ = e;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        eprintln!("[handoff] the scan listener could not start: {e}");
                        break;
                    }
                }
            }
        }
    }

    // Background watcher for engine ready -> auto-start scan server if configured
    let app_clone = Arc::clone(&app_state);
    let engine_clone = Arc::clone(&engine);
    let archive = args.archive;
    tokio::spawn(async move {
        if standby {
            return; // started above
        }
        while !archive && !engine_clone.is_ready().await {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let settings = app_clone.settings.read().await.clone();
        if settings.autostart {
            if let Err(e) = app_clone.start_listener(settings).await {
                app_clone.events.add(crate::events::Event {
                    seq: 0,
                    time: chrono::Utc::now(),
                    kind: "info".to_string(),
                    session: None,
                    client: None,
                    verdict: None,
                    file: None,
                    size: None,
                    ms: None,
                    threat: None,
                    detail: None,
                    sha256: None,
                    message: Some(format!("auto start failed: {}", e)),
                    origin_type: None,
                });
            }
        }
    });

    // Start Dashboard HTTP Server on UI port (default 127.0.0.1:9440); after a
    // seamless-update takeover it is already bound.
    let dash_listener = match early_dashboard {
        Some(l) => l,
        None => tokio::net::TcpListener::bind(ui_addr).await?,
    };
    let dash_url = format!("http://{}/", dash_listener.local_addr()?);
    eprintln!("dashboard: {}", dash_url);

    if !args.no_browser && !standby {
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("rundll32")
                .args(["url.dll,FileProtocolHandler", &dash_url])
                .spawn();
        }
    }

    let dash_router = dashboard_router(Arc::clone(&app_state));

    let shutdown_app = Arc::clone(&app_state);
    let serve_fut = axum::serve(
        dash_listener,
        dash_router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("shutting down...");
        uptime::save_now();
        shutdown_app.stop_listener(false).await;
    });

    serve_fut.await?;
    Ok(())
}

/// Kept-file and review-queue upkeep at start (legacy layouts, human verdicts,
/// duplicates). After a seamless-update takeover it runs in the background.
fn startup_upkeep(engine: &Arc<EngineAdapter>, ti: &Arc<threat_intel::ThreatIntelStore>) {
    engine.sort_legacy_kept(|sha| ti.get(sha).map(|i| i.verdict));
    // Kept files follow human verdicts (e.g. bulk whitelists made by older builds).
    let queued = ti.sync_review_queue();
    if queued > 0 {
        eprintln!("[review] {queued} open files added to the human analysis queue");
    }
    let moved = engine.relabel_many(&ti.reviews.completed_verdicts());
    if moved > 0 {
        eprintln!("[engine] {moved} kept files moved to the folder of their human verdict");
    }
    let (dups, bytes) = engine.dedupe_kept(|sha| {
        let (verdict, source, _) = ti.effective(&sha.to_ascii_lowercase());
        (source != "unseen").then_some(verdict)
    });
    if dups > 0 {
        eprintln!("[engine] {dups} duplicate kept files removed ({:.1} MB)", bytes as f64 / 1048576.0);
    }
    // ML dataset files follow human verdicts too (applied when the index is ready).
    if let Some(ds) = engine.dataset.get() {
        ds.apply_human_verdicts(&ti.reviews.completed_verdicts());
    }
}
