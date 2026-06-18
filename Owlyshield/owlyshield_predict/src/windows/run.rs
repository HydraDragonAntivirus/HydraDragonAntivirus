#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::behavioral::app_settings::AppSettings;
use crate::config::Param;
use crate::connectors::register::Connectors;
use crate::shared_def::IOMessage;
use crate::threathandling::WindowsThreatHandler;
use crate::watchlist::WatchList;
use crate::worker::process_record_handling::{
    ExepathLive, ProcessRecordHandlerLive,
};
use crate::worker::worker_instance::{
    IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Worker,
};
use crate::{Driver, Logging, config};

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
#[derive(Debug, Clone)]
struct KernelExcludeRulePaths {
    fsfilter: PathBuf,
    dynamic_hook: PathBuf,
    process_protection: PathBuf,
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn normalize_kernel_rule_entry(line: &str) -> Option<String> {
    let trimmed = line.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    let normalized = trimmed.replace('/', "\\").to_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|existing| existing == &candidate) {
        paths.push(candidate);
    }
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn hydra_dragon_root_candidates() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(root) = crate::globals::rules_path()
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
    {
        push_unique_path(&mut roots, root);
    }

    if let Some(root) = crate::globals::config_path()
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
    {
        push_unique_path(&mut roots, root);
    }

    roots
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn select_existing_or_first(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    if candidates.is_empty() {
        return None;
    }

    candidates
        .iter()
        .find(|candidate| candidate.exists())
        .cloned()
        .or_else(|| candidates.into_iter().next())
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn firewall_gui_path_candidates() -> Vec<PathBuf> {
    vec![PathBuf::from(
        r"C:\Program Files\HydraDragonAntivirus\hydradragon\HydraDragonFirewall\HydraDragonFirewall.exe",
    )]
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn firewall_gui_exclude_candidates() -> BTreeSet<String> {
    let mut entries = BTreeSet::new();

    for firewall_exe in firewall_gui_path_candidates() {
        if let Some(normalized) = normalize_kernel_rule_entry(&firewall_exe.to_string_lossy()) {
            entries.insert(normalized);
        }
    }

    entries
}

pub fn run() {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        println!("{pi}");
        Logging::error(format!("Critical error: {pi}").as_str());
    }));

    Logging::start();

    // Open driver early (used for realtime handling in main loop)
    let driver = Driver::open_kernel_driver_com()
        .expect("Cannot open driver communication (is the minifilter started?)");
    driver
        .driver_set_app_pid()
        .expect("Cannot set driver app pid");

    // Load config and app settings once and reuse
    let config = config::Config::new();
    crate::globals::init_globals(&config);
    let _current_exe_path = std::env::current_exe().unwrap();
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    let rules_dir = crate::globals::rules_path().to_path_buf();

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    Logging::info(&format!(
        "[Owlyshield] Using rules directory: {:?}",
        rules_dir
    ));

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    let app_settings = AppSettings::load(&rules_dir)
        .map_err(|e| {
            Logging::error(&format!(
                "Failed to load app settings from rules/settings.yaml at {:?}: {}",
                rules_dir, e
            ));
            e
        })
        .expect("Critical: Failed to load app settings");

    // Replay mode: process stored driver messages and exit the run function
    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");

        // For replay we load a separate AppSettings instance if behavior engine is enabled
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let app_settings_replay =
            AppSettings::load(&rules_dir).expect("Failed to load app settings for replay");

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let mut worker = Worker::new_replay(&config, app_settings_replay).driver(driver.clone());
        #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
        let mut worker = Worker::new_replay(&config);

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        {
            let rules_path = worker.app_settings.behavior_rules_path.clone();
            if let Err(e) = worker.behavior_engine.load_rules(&rules_path) {
                Logging::error(&format!(
                    "Failed to load behavior rules for replay from {:?}: {}",
                    rules_path, e
                ));
            }
        }

        let filename =
            &Path::new(&config[Param::RealTimeLearningPath]).join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = vec![0; buf_size];
        let mut cursor_index = 0;

        while cursor_index < file_len {
            buf.fill(0);
            file.seek(SeekFrom::Start(cursor_index as u64)).unwrap();

            // Read remaining bytes if less than buf_size
            let bytes_remaining = file_len - cursor_index;
            let bytes_to_read = bytes_remaining.min(buf_size);

            if bytes_to_read < buf_size {
                // Partial read for the final chunk
                file.read_exact(&mut buf[0..bytes_to_read]).unwrap();
            } else {
                file.read_exact(&mut buf).unwrap();
            }

            let mut cursor_record_end = bytes_to_read;
            for i in 0..(bytes_to_read.saturating_sub(3)) {
                // A strange chain is used to avoid collisions with the windows fileid
                if buf[i] == 255u8 && buf[i + 1] == 0u8 && buf[i + 2] == 13u8 && buf[i + 3] == 10u8
                {
                    cursor_record_end = i;
                    break;
                }
            }

            match rmp_serde::from_slice(&buf[0..cursor_record_end]) {
                Ok(mut iomsg) => {
                    worker.process_io(&mut iomsg, &config);
                }
                Err(_e) => {
                    println!("Error deserializing buffer at offset {cursor_index}");
                }
            }

            cursor_index += cursor_record_end + 4;
        }

        // After replay we return instead of continuing into realtime logic
        return;
    }

    // Non-replay (realtime) mode
    if cfg!(not(feature = "replay")) {
        if cfg!(feature = "malware") {
            println!("\nMALWARE PROTECTION MODE");
        }
        if cfg!(feature = "record") {
            println!("\nRECORD");
        }
        println!("Interactive - can also work as a service.\n");

        // tx_iomsgs is intentionally unused in the current pipe-driven architecture.
        // IOMessages from edrdrv flow via edrsvc → HydraDragonOpenEdrTelemetry pipe →
        // ingest_openedr_event → pending_irp_records → drain_pending_irp_records.
        // The rx_iomsgs worker loop below is retained for future direct IOCTL feed.
        let (_tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

        // Run connectors and the worker thread
        Connectors::on_startup(&config);

        // Spawn the worker thread that consumes IO messages and performs analysis
        let thread_config = config; // moved into thread
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let thread_app_settings = app_settings; // moved into thread
        let thread_driver = driver.clone();
        thread::spawn(move || {
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            let mut worker =
                Worker::new(&thread_config, thread_app_settings).driver(thread_driver.clone());
            #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
            let mut worker = Worker::new(&thread_config).driver(thread_driver.clone());

            // Initialize threat handler early to reuse the driver connection
            let win_threat_handler = WindowsThreatHandler::from(thread_driver.clone());
            worker = worker.threat_handler(Box::new(win_threat_handler.clone()));

            #[cfg(all(target_os = "windows", feature = "hydradragon"))]
            {
                let hydra_dragon_integration =
                    crate::init_hydra_dragon(&thread_config, thread_driver.clone());
                worker = worker.av_integration(hydra_dragon_integration);

                // Start Suricata NIDS and Hayabusa EVTX scanner in Rust
                crate::hydradragon::suricata::start_suricata_monitor();
                crate::hydradragon::hayabusa::start_hayabusa_monitor();
            }

            worker = worker.exepath_handler(Box::new(ExepathLive));

            if cfg!(feature = "malware") {
                worker = worker.process_record_handler(Box::new(ProcessRecordHandlerLive::new(
                    &thread_config,
                    Box::new(win_threat_handler.clone()),
                )));
            }

            if cfg!(feature = "record") {
                worker = worker.register_iomsg_postprocessor(Box::new(
                    IOMsgPostProcessorWriter::from(&thread_config),
                ));
            }

            if cfg!(feature = "jsonrpc") {
                worker =
                    worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()));
            }

            if cfg!(feature = "mqtt") {
                worker = worker.register_iomsg_postprocessor(Box::new(
                    IOMsgPostProcessorMqtt::new(thread_config[Param::MqttServer].clone()),
                ));
            }

            worker = worker.build();

            // Load behavior rules
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                let rules_path = worker.app_settings.behavior_rules_path.clone();
                Logging::info(&format!(
                    "[Owlyshield] Handing rules off to BehaviorEngine from path: {:?}",
                    rules_path
                ));
                if let Err(e) = worker.behavior_engine.load_rules(&rules_path) {
                    Logging::error(&format!(
                        "Failed to load behavior rules from {:?}: {}",
                        rules_path, e
                    ));
                }
            }

            worker.discover_existing_processes();

            // --- Event-driven worker loop ---
            // Detection runs inline on each event. Keep only lightweight
            // housekeeping on a short cadence for suspended/dead records.
            let mut last_housekeeping = std::time::Instant::now();
            let housekeeping_interval = std::time::Duration::from_millis(750);
            let mut msgs_since_housekeeping: usize = 0;
            loop {
                let iomsg_res = rx_iomsgs.recv_timeout(std::time::Duration::from_millis(250));
                if let Ok(mut iomsg) = iomsg_res {
                    worker.process_io(&mut iomsg, &thread_config);
                    msgs_since_housekeeping += 1;
                } else if let Err(std::sync::mpsc::RecvTimeoutError::Disconnected) = iomsg_res {
                    break;
                }

                if msgs_since_housekeeping >= 256
                    || last_housekeeping.elapsed() >= housekeeping_interval
                {
                    let th_opt = worker.threat_handler.as_ref().map(|h| h.clone_box());
                    if let Some(th) = th_opt {
                        worker.validate_tracked_processes();
                        worker.scan_processes(&thread_config, th.clone_box());
                        worker.process_suspended_records(&thread_config, th);
                    }
                    msgs_since_housekeeping = 0;
                    last_housekeeping = std::time::Instant::now();
                }
            }
        });

        // Main thread: kernel telemetry is received via edrsvc named pipe.
        // edrsvc.exe reads from edrdrv and forwards all events (opcodes 0-30+)
        // to Owlyshield over \\.\pipe\Global\HydraDragonOpenEdrTelemetry.
        // Worker thread above consumes IOMessages from rx_iomsgs channel.
        // This thread parks itself — all work is pipe-driven.
        Logging::info("[Owlyshield] Main thread parked. Telemetry via edrsvc pipe.");
        loop {
            thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
