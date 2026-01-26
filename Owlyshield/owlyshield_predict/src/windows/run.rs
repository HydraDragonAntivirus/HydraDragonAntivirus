use std::fs::File;
use std::path::{Path, PathBuf};
use std::thread;
use std::sync::mpsc::channel;
use std::io::{Read, Seek, SeekFrom};

use crate::{
    CDriverMsgs, config, Connectors, Driver, ExepathLive, IOMessage,
    IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter,
    Logging, ProcessRecordHandlerLive, whitelist, Worker, ProcessRecordHandlerNovelty,
};
use crate::config::Param;
use crate::watchlist::WatchList;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::behavioral::app_settings::AppSettings;
use crate::threathandling::WindowsThreatHandler;

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

    let mut vecnew: Vec<u8> = Vec::with_capacity(65536);

    // Load config and app settings once and reuse
    let config = config::Config::new();
    let _current_exe_path = std::env::current_exe().unwrap();
    let rules_dir = PathBuf::from(&config[Param::RulesPath]);
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    let app_settings = AppSettings::load(&rules_dir)
        .expect("Failed to load app settings from rules/settings.yaml");

    // Replay mode: process stored driver messages and exit the run function
    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");

        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[Param::ConfigPath]).join(Path::new("exclusions.txt")),
        )
        .unwrap();

        // For replay we load a separate AppSettings instance if behavior engine is enabled
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let app_settings_replay = AppSettings::load(&rules_dir)
            .expect("Failed to load app settings for replay");

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let mut worker = Worker::new_replay(&config, &whitelist, app_settings_replay);
        #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
        let mut worker = Worker::new_replay(&config, &whitelist);

        let filename = &Path::new(&config[Param::ProcessActivityLogPath])
            .join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
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
        if cfg!(feature = "novelty") {
            println!("\nNOVELTY PROTECTION MODE");
        }
        if cfg!(feature = "record") {
            println!("\nRECORD");
        }
        println!("Interactive - can also work as a service.\n");

        let (tx_iomsgs, rx_iomsgs) = channel::<IOMessage>();

        // Run connectors and the worker thread
        Connectors::on_startup(&config);

        // Spawn the worker thread that consumes IO messages and performs analysis
        let thread_config = config; // moved into thread
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let thread_app_settings = app_settings; // moved into thread
        thread::spawn(move || {
            let whitelist = whitelist::WhiteList::from(
                &Path::new(&thread_config[Param::ConfigPath]).join(Path::new("exclusions.txt")),
            )
            .expect("Cannot open exclusions.txt");

            whitelist.refresh_periodically();

            if cfg!(feature = "novelty") {
                let watchlist = WatchList::from(
                    &Path::new(&thread_config[Param::NoveltyPath]).join(Path::new("to_analyze.yml")),
                )
                .expect("Cannot open to_analyze.yml");
                watchlist.refresh_periodically();
            }

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            let mut worker = Worker::new(&thread_config, thread_app_settings);
            #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
            let mut worker = Worker::new(&thread_config);

            // Initialize threat handler early to reuse the driver connection
            let win_threat_handler = WindowsThreatHandler::from(driver);
            worker = worker.threat_handler(Box::new(win_threat_handler.clone()));

            #[cfg(all(target_os = "windows", feature = "hydradragon"))]
            {
                let hydra_dragon_integration = crate::init_hydra_dragon(&thread_config);
                worker = worker.av_integration(hydra_dragon_integration);
            }

            worker = worker.exepath_handler(Box::new(ExepathLive::default()));

            if cfg!(feature = "malware") {
                worker = worker
                    .whitelist(&whitelist)
                    .process_record_handler(Box::new(ProcessRecordHandlerLive::new(
                        &thread_config,
                        Box::new(win_threat_handler.clone()),
                    )));
            }

            if cfg!(feature = "novelty") {
                let watchlist = WatchList::from(
                    &Path::new(&thread_config[Param::NoveltyPath]).join(Path::new("to_analyze.yml")),
                )
                .expect("Cannot open to_analyze.yml");
                watchlist.refresh_periodically();

                worker = worker.process_record_handler(Box::new(ProcessRecordHandlerNovelty::new(
                    &thread_config,
                    watchlist,
                )));
            }

            if cfg!(feature = "record") {
                worker = worker.register_iomsg_postprocessor(Box::new(
                    IOMsgPostProcessorWriter::from(&thread_config),
                ));
            }

            if cfg!(feature = "jsonrpc") {
                worker = worker.register_iomsg_postprocessor(Box::new(IOMsgPostProcessorRPC::new()));
            }

            if cfg!(feature = "mqtt") {
                worker = worker.register_iomsg_postprocessor(Box::new(
                    IOMsgPostProcessorMqtt::new(thread_config[Param::MqttServer].clone()),
                ));
            }

            worker = worker.build();

            // Load behavior rules
            #[cfg(feature = "behavior_engine")]
            {
                let rules_path = worker.app_settings.behavior_rules_path.clone();
                if let Err(e) = worker.behavior_engine.load_rules(&rules_path) {
                    Logging::error(&format!("Failed to load behavior rules from {:?}: {}", rules_path, e));
                }
            }

            worker.discover_existing_processes();

            // --- Event-driven worker loop: immediate processing with direct scanning ---
            loop {
                let mut iomsg = match rx_iomsgs.recv() {
                    Ok(msg) => msg,
                    Err(_) => break, // channel disconnected
                };

                // Process the incoming IO message immediately
                worker.process_io(&mut iomsg, &thread_config);

                // Immediately run scans and suspended-record processing after every message
                // No throttling - direct scan on every event
                if let Some(handler) = worker.threat_handler.as_ref() {
                    let th_scan = handler.clone_box();
                    let th_suspended = handler.clone_box();

                    worker.scan_processes(&thread_config, th_scan);
                    worker.process_suspended_records(&thread_config, th_suspended);
                }
            }
        });

        // Main thread: read driver messages and forward to worker thread
        loop {
            match driver.get_irp(&mut vecnew) {
                Ok(Some(reply_irp)) => {
                    if reply_irp.num_ops > 0 {
                        let drivermsgs = CDriverMsgs::new(&reply_irp);
                        for drivermsg in drivermsgs {
                            let iomsg = IOMessage::from_driver_msg(&drivermsg);
                            if tx_iomsgs.send(iomsg).is_err() {
                                println!("Cannot send iomsg");
                                Logging::error("Cannot send iomsg");
                            }
                        }
                    }
                }
                Ok(None) => {
                    // No messages, small sleep to prevent 100% CPU
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    // Don't panic, log and wait before retry
                    Logging::error(&format!("Driver communication error (HRESULT: 0x{:X})", e.code().0));
                    thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }
}
