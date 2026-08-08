
use std::sync::mpsc::channel;
use std::thread;


use crate::behavioral::app_settings::AppSettings;
use crate::connectors::register::Connectors;
use crate::shared_def::IOMessage;
use crate::threathandling::WindowsThreatHandler;
use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive};
use crate::worker::worker_instance::Worker;
use crate::{Driver, Logging, config};

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
    
    let rules_dir = crate::globals::rules_path().to_path_buf();

    
    Logging::info(&format!(
        "[Owlyshield] Using rules directory: {:?}",
        rules_dir
    ));

    
    let app_settings = AppSettings::load(&rules_dir)
        .map_err(|e| {
            Logging::error(&format!(
                "Failed to load app settings from rules/settings.yaml at {:?}: {}",
                rules_dir, e
            ));
            e
        })
        .expect("Critical: Failed to load app settings");

    println!("Interactive - can also work as a service.\n");

    let (_tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

    // Run connectors and the worker thread
    Connectors::on_startup(&config);

    // Spawn the worker thread that consumes IO messages and performs analysis
    let thread_config = config; // moved into thread
    
    let thread_app_settings = app_settings; // moved into thread
    let thread_driver = driver.clone();
    thread::spawn(move || {
        
        let mut worker =
            Worker::new(&thread_config, thread_app_settings).driver(thread_driver.clone());

        // Initialize threat handler early to reuse the driver connection
        let win_threat_handler = WindowsThreatHandler::from(thread_driver.clone());
        worker = worker.threat_handler(Box::new(win_threat_handler.clone()));

        worker = worker.exepath_handler(Box::new(ExepathLive));

        worker = worker.process_record_handler(Box::new(ProcessRecordHandlerLive::new(
            &thread_config,
            Box::new(win_threat_handler.clone()),
        )));

        worker = worker.build();

        // Load behavior rules
        {
            let rules_path = crate::globals::rules_path();
            Logging::info(&format!(
                "[Owlyshield] Handing rules off to BehaviorEngine from path: {:?}",
                rules_path
            ));
            if let Err(e) = worker.behavior_engine.load_rules(rules_path) {
                Logging::error(&format!(
                    "Failed to load behavior rules from {:?}: {}",
                    rules_path, e
                ));
            }

            let firewall_rules_path = rules_path.join("firewall-rules");
            if firewall_rules_path.exists() {
                Logging::info(&format!(
                    "[Owlyshield] Loading firewall rules off to BehaviorEngine from path: {:?}",
                    firewall_rules_path
                ));
                if let Err(e) = worker.behavior_engine.load_rules(&firewall_rules_path) {
                    Logging::error(&format!(
                        "Failed to load firewall behavior rules from {:?}: {}",
                        firewall_rules_path, e
                    ));
                }
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
/// Entry point for the DLL worker loop used by `ffi.rs`.
/// Receives IOMessages from `edrsvc` and processes them through the behavior engine.
pub fn run_worker_loop(rx: std::sync::mpsc::Receiver<crate::shared_def::IOMessage>, _driver: crate::windows::edrsvc_client::Driver) {
    
    use crate::behavioral::app_settings::AppSettings;

    let config = crate::config::Config::new();

    
    let mut worker = crate::worker::worker_instance::Worker::new(&config, AppSettings::default());

    for mut iomsg in rx {
        worker.process_io(&mut iomsg, &config);
    }
}
