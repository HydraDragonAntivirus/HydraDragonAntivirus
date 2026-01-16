use std::fs::File;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};
use std::sync::mpsc::channel;
use std::io::{Read, Seek, SeekFrom};

use crate::{
    CDriverMsgs, config, Connectors, Driver, ExepathLive, IOMessage,
    IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter,
    Logging, ProcessRecordHandlerLive, whitelist, Worker, ProcessRecordHandlerNovelty,
};
use crate::config::Param;
use crate::watchlist::WatchList;
use crate::app_settings::AppSettings;
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
    let app_settings = AppSettings::load(&rules_dir)
        .expect("Failed to load app settings from rules/settings.yaml");

    // Replay mode: process stored driver messages and exit the run function
    if cfg!(feature = "replay") {
        println!("Replay Driver Messages");

        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[Param::ConfigPath]).join(Path::new("exclusions.txt")),
        )
        .unwrap();

        // For replay we load a separate AppSettings instance so we don't move `app_settings` used below
        let app_settings_replay = AppSettings::load(&rules_dir)
            .expect("Failed to load app settings for replay");

        let mut worker = Worker::new_replay(&config, &whitelist, app_settings_replay);

        let filename = &Path::new(&config[Param::ProcessActivityLogPath])
            .join(Path::new("drivermessages.txt"));
        let mut file = File::open(Path::new(filename)).unwrap();
        let file_len = file.metadata().unwrap().len() as usize;

        let buf_size = 1000;
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(buf_size, 0);
        let mut cursor_index = 0;

        while cursor_index + buf_size < file_len {
            // TODO ToFix! last 1000 buffer ignored
            buf.fill(0);
            file.seek(SeekFrom::Start(cursor_index as u64)).unwrap();
            file.read_exact(&mut buf).unwrap();

            let mut cursor_record_end = buf_size;
            for i in 0..(buf_size - 3) {
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
                    println!("Error deserializing buffer {cursor_index}"); // buffer is too small
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

        // Run connectors and the worker thread (no redundant cfg!(not(feature = "replay")) check)
        Connectors::on_startup(&config);

        // Spawn the worker thread that consumes IO messages and performs analysis
        let thread_config = config; // moved into thread
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

            let mut worker = Worker::new(&thread_config, thread_app_settings);

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
                        Box::new(WindowsThreatHandler::from(driver)),
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
            let rules_path = worker.app_settings.behavior_rules_path.clone();
            if let Err(e) = worker.behavior_engine.load_rules(&rules_path) {
                Logging::error(&format!("Failed to load behavior rules from {:?}: {}", rules_path, e));
            }

            // --- REALTIME LEARNING INTEGRATION ---
            #[cfg(feature = "realtime_learning")]
            {
                use crate::realtime_learning::RealtimeLearningEngine;
                let rules_dir = Path::new(&thread_config[Param::RulesPath]);
                let learner = RealtimeLearningEngine::new(
                    rules_dir.to_str().unwrap_or("."),
                    Some(worker.app_settings.win_verify_trust_path.to_str().unwrap()),
                );

                // 1. Process Quarantine Logs
                let quarantine_path = Path::new(r"C:\ProgramData\HydraDragonAntivirus\Quarantine_Log\quarantine_log.json");
                let learned_rules = learner.process_quarantine_log(quarantine_path);

                if !learned_rules.is_empty() {
                    Logging::info(&format!(
                        "Realtime Learning: Generated {} rules from quarantine history",
                        learned_rules.len()
                    ));

                    // 2. Save Rules
                    let learned_rules_path = rules_dir.join("learned_rules.yaml");
                    if let Err(e) = learner.save_rules_to_yaml(&learned_rules, &learned_rules_path) {
                        Logging::error(&format!("Failed to save learned rules: {}", e));
                    } else {
                        // 3. Load Rules into Engine
                        if let Err(e) = worker.behavior_engine.load_additional_rules(&learned_rules_path) {
                            Logging::error(&format!("Failed to load learned rules: {}", e));
                        }
                    }
                }
            }

            let mut count = 0;
            let mut timer = SystemTime::now();

            loop {
                let mut iomsg = rx_iomsgs.recv().unwrap();
                worker.process_io(&mut iomsg, &thread_config);

                if count > 200 && SystemTime::now().duration_since(timer).unwrap() > Duration::from_secs(3) {
                    worker.scan_processes();
                    worker.process_suspended_records(&thread_config, Box::new(WindowsThreatHandler::from(driver)));
                    count = 0;
                    timer = SystemTime::now();
                }

                count += 1;
            }
        });

        // Main thread: read driver messages and forward to worker thread
        loop {
            if let Some(reply_irp) = driver.get_irp(&mut vecnew) {
                if reply_irp.num_ops > 0 {
                    let drivermsgs = CDriverMsgs::new(&reply_irp);
                    for drivermsg in drivermsgs {
                        let iomsg = IOMessage::from_driver_msg(&drivermsg);
                        if tx_iomsgs.send(iomsg).is_ok() {
                        } else {
                            println!("Cannot send iomsg");
                            Logging::error("Cannot send iomsg");
                        }
                    }
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            } else {
                panic!("Can't receive Driver Message?");
            }
        }
    }
}
