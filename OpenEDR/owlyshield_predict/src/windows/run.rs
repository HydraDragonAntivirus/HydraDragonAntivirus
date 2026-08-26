use std::sync::mpsc::channel;
use std::thread;

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

    // Initialize the in-process OpenEDR telemetry channel before the worker
    // thread starts so the consumer thread can attach.
    crate::ffi::init_telemetry_channel();

    // Open driver early (used for realtime handling in main loop)
    let driver = Driver::open_kernel_driver_com()
        .expect("Cannot open driver communication (is the minifilter started?)");
    driver
        .driver_set_app_pid()
        .expect("Cannot set driver app pid");

    // Load config once and reuse
    let config = config::Config::new();
    crate::globals::init_globals(&config);
    let _current_exe_path = std::env::current_exe().unwrap();

    println!("Interactive - can also work as a service.\n");

    let (_tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

    // Run connectors and the worker thread
    Connectors::on_startup(&config);

    // Install + start the MBRFilter kernel driver and listen for MBR write
    // alerts (best effort; failures are logged, never fatal).
    crate::windows::mbrfilter::ensure_mbrfilter_driver();
    crate::windows::mbrfilter::spawn_mbr_alert_listener();

    // Spawn the worker thread that consumes IO messages and performs analysis
    let thread_config = config; // moved into thread
    let thread_driver = driver.clone();
    thread::spawn(move || {
        let mut worker = Worker::new(&thread_config).driver(thread_driver.clone());

        // Initialize threat handler early to reuse the driver connection
        let win_threat_handler = WindowsThreatHandler::from(thread_driver.clone());
        worker = worker.threat_handler(Box::new(win_threat_handler.clone()));

        worker = worker.exepath_handler(Box::new(ExepathLive));

        worker = worker.process_record_handler(Box::new(ProcessRecordHandlerLive::new(
            &thread_config,
            Box::new(win_threat_handler.clone()),
        )));

        worker = worker.build();

        worker.discover_existing_processes();

        // --- Event-driven worker loop ---
        // Detection runs inline on each event. Keep only lightweight
        // housekeeping on a short cadence for suspended/dead records.
        let mut last_housekeeping = std::time::Instant::now();
        let housekeeping_interval = std::time::Duration::from_millis(750);
        let mut msgs_since_housekeeping: usize = 0;
        loop {
            let iomsg_res = rx_iomsgs.recv_timeout(std::time::Duration::from_millis(20));
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
                    worker.scan_processes(&thread_config);
                    worker.process_suspended_records(&thread_config, th);
                }
                msgs_since_housekeeping = 0;
                last_housekeeping = std::time::Instant::now();
            }
        }
    });

    // Main thread: kernel telemetry is received from edrsvc directly.
    // edrsvc.exe reads from edrdrv and forwards all events (opcodes 0-30+)
    // to Owlyshield via the in-process FFI telemetry channel.
    // Worker thread above consumes IOMessages from rx_iomsgs channel.
    // This thread parks itself â€” all work is channel-driven.
    Logging::info("[Owlyshield] Main thread parked. Telemetry via edrsvc FFI.");
    loop {
        thread::sleep(std::time::Duration::from_secs(60));
    }
}
/// Entry point for the DLL worker loop used by `ffi.rs`.
/// Receives IOMessages from `edrsvc` and processes them through the worker.
/// A short-cadence housekeeping loop drives process discovery and dynamic
/// kernel-hook registration (`scan_processes` -> `MESSAGE_HOOK_PROCESS`) that
/// otherwise never runs in the in-process FFI architecture.
pub fn run_worker_loop(
    rx: std::sync::mpsc::Receiver<crate::shared_def::IOMessage>,
    driver: crate::windows::edrsvc_client::Driver,
) {
    let config = crate::config::Config::new();
    crate::globals::init_globals(&config);

    // Install + start the MBRFilter kernel driver and listen for MBR write
    // alerts (best effort; failures are logged, never fatal).
    crate::windows::mbrfilter::ensure_mbrfilter_driver();
    crate::windows::mbrfilter::spawn_mbr_alert_listener();

    let mut worker = crate::worker::worker_instance::Worker::new(&config).driver(driver.clone());

    // Initialize threat handler early to reuse the driver connection
    let win_threat_handler = WindowsThreatHandler::from(driver.clone());
    worker = worker.threat_handler(Box::new(win_threat_handler.clone()));

    worker = worker.exepath_handler(Box::new(ExepathLive));

    worker = worker.process_record_handler(Box::new(ProcessRecordHandlerLive::new(
        &config,
        Box::new(win_threat_handler.clone()),
    )));

    worker = worker.build();

    worker.discover_existing_processes();

    // Event-driven loop with periodic housekeeping that discovers new processes
    // and registers dynamic kernel hooks. Telemetry event parsing and detection
    // decisions stay on the OpenEDR side.
    let mut last_housekeeping = std::time::Instant::now();
    let housekeeping_interval = std::time::Duration::from_millis(750);
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(20)) {
            Ok(mut iomsg) => {
                worker.process_io(&mut iomsg, &config);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }

        if last_housekeeping.elapsed() >= housekeeping_interval {
            let th_opt = worker.threat_handler.as_ref().map(|h| h.clone_box());
            if let Some(th) = th_opt {
                worker.validate_tracked_processes();
                worker.scan_processes(&config);
                worker.process_suspended_records(&config, th);
            }
            last_housekeeping = std::time::Instant::now();
        }
    }
}
