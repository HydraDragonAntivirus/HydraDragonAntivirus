mod budget;
mod cache;
mod config;
mod dashboard;
mod engine_adapter;
mod events;
mod limits;
mod ratelimit;
mod scan_server;
mod scheduler;
mod threat_intel;

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
        args.compress_low_disk(),
        args.low_disk_gb,
    );
    let custom_rules = if args.rules.is_empty() {
        None
    } else {
        Some(PathBuf::from(&args.rules))
    };
    engine.start_loading(custom_rules);

    let threat_intel = threat_intel::ThreatIntelStore::new(None);
    let scan_server = ScanServer::new(
        args.clone(),
        Arc::clone(&engine),
        Arc::clone(&events),
        Arc::clone(&threat_intel),
    );
    let app_state = AppState::new(
        args.clone(),
        Arc::clone(&engine),
        Arc::clone(&events),
        Arc::clone(&scan_server),
        Arc::clone(&threat_intel),
    )
    .await;

    // Background watcher for engine ready -> auto-start scan server if configured
    let app_clone = Arc::clone(&app_state);
    let engine_clone = Arc::clone(&engine);
    tokio::spawn(async move {
        while !engine_clone.is_ready().await {
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

    // Start Dashboard HTTP Server on UI port (default 127.0.0.1:9440)
    let ui_addr: SocketAddr = args
        .ui
        .parse()
        .map_err(|e| format!("invalid --ui address '{}': {}", args.ui, e))?;

    let dash_listener = tokio::net::TcpListener::bind(ui_addr).await?;
    let dash_url = format!("http://{}/", dash_listener.local_addr()?);
    eprintln!("dashboard: {}", dash_url);

    if !args.no_browser {
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
        shutdown_app.stop_listener(false).await;
    });

    serve_fut.await?;
    Ok(())
}
