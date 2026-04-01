#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use std::collections::BTreeSet;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::channel;
use std::thread;

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::behavioral::app_settings::AppSettings;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::behavioral::behavior_engine::BehaviorRule;
use crate::config::Param;
use crate::shared_def::IrpMajorOp;
use crate::threathandling::WindowsThreatHandler;
#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::utils::format_process_descriptor_with_fallback;
use crate::watchlist::WatchList;
use crate::{
    CDriverMsgs, Connectors, Driver, ExepathLive, IOMessage, IOMsgPostProcessorMqtt,
    IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Logging, ProcessRecordHandlerLive,
    ProcessRecordHandlerNovelty, Worker, config, whitelist,
};

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
const FSFILTER_EXCLUDE_RULE_FILE: &str = r"C:\Program Files\HydraDragonAntivirus\hydradragon\PYAS_Protection\PYAS_Protection_Rules\Process\Owlyshield\FsFilter\default_rules.txt";

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
fn collect_kernel_exclude_entries(rules: &[BehaviorRule]) -> BTreeSet<String> {
    let mut entries = BTreeSet::new();
    for rule in rules {
        for path in &rule.protected_paths.file_paths {
            if let Some(normalized) = normalize_kernel_rule_entry(path) {
                entries.insert(normalized);
            }
        }
    }
    entries
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn sync_kernel_exclude_rule_file(
    path: &Path,
    dynamic_entries: &BTreeSet<String>,
) -> std::io::Result<()> {
    let mut merged = BTreeSet::new();

    if let Ok(existing) = fs::read_to_string(path) {
        for line in existing.lines() {
            if let Some(normalized) = normalize_kernel_rule_entry(line) {
                merged.insert(normalized);
            }
        }
    }

    merged.extend(dynamic_entries.iter().cloned());

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut output = String::from(
        "# Auto-synced Owlyshield filesystem exclude rules.\r\n# Merged from behavior rules protected_paths.file_paths and existing manual entries.\r\n\r\n",
    );
    for entry in merged {
        output.push_str(&entry);
        output.push_str("\r\n");
    }

    fs::write(path, output)
}

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
fn sync_kernel_exclude_rules(
    rules: &[BehaviorRule],
    driver: &Driver,
) -> Result<(), Box<dyn std::error::Error>> {
    let dynamic_entries = collect_kernel_exclude_entries(rules);
    if dynamic_entries.is_empty() {
        return Ok(());
    }

    sync_kernel_exclude_rule_file(Path::new(FSFILTER_EXCLUDE_RULE_FILE), &dynamic_entries)?;

    driver.reload_exclude_rules()?;
    Ok(())
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
    Logging::info("[VMM MODE] Dynamic MESSAGE_ADD_HOOK registration is enabled");

    let mut vecnew: Vec<u8> = vec![0u8; 65536];

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

        let whitelist = whitelist::WhiteList::from(
            &Path::new(&config[Param::ConfigPath]).join(Path::new("exclusions.txt")),
        )
        .unwrap();

        // For replay we load a separate AppSettings instance if behavior engine is enabled
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let app_settings_replay =
            AppSettings::load(&rules_dir).expect("Failed to load app settings for replay");

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let mut worker =
            Worker::new_replay(&config, &whitelist, app_settings_replay).driver(driver.clone());
        #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
        let mut worker = Worker::new_replay(&config, &whitelist);

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
        let thread_driver = driver.clone();
        thread::spawn(move || {
            let whitelist = whitelist::WhiteList::from(
                &Path::new(&thread_config[Param::ConfigPath]).join(Path::new("exclusions.txt")),
            )
            .expect("Cannot open exclusions.txt");

            whitelist.refresh_periodically();

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
                let hydra_dragon_integration = crate::init_hydra_dragon(&thread_config);
                worker = worker.av_integration(hydra_dragon_integration);
            }

            worker = worker.exepath_handler(Box::new(ExepathLive));

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
                    &Path::new(&thread_config[Param::NoveltyPath])
                        .join(Path::new("to_analyze.yml")),
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
            #[cfg(feature = "behavior_engine")]
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
                } else if let Err(e) =
                    sync_kernel_exclude_rules(&worker.behavior_engine.rules, &thread_driver)
                {
                    Logging::error(&format!("Failed to sync kernel exclude rules: {}", e));
                }
            }

            worker.discover_existing_processes();

            // --- Event-driven worker loop ---
            // Detection runs inline on each event. Keep only lightweight
            // housekeeping on a short cadence for suspended/dead records.
            let mut last_housekeeping = std::time::Instant::now();
            let housekeeping_interval = std::time::Duration::from_millis(750);
            let mut msgs_since_housekeeping: usize = 0;
            while let Ok(mut iomsg) = rx_iomsgs.recv() {
                // Process the incoming IO message immediately
                worker.process_io(&mut iomsg, &thread_config);

                msgs_since_housekeeping += 1;
                if msgs_since_housekeeping >= 256
                    || last_housekeeping.elapsed() >= housekeeping_interval
                {
                    if let Some(handler) = worker.threat_handler.as_ref() {
                        let th_suspended = handler.clone_box();
                        worker.validate_tracked_processes();
                        worker.process_suspended_records(&thread_config, th_suspended);
                    }
                    msgs_since_housekeeping = 0;
                    last_housekeeping = std::time::Instant::now();
                }
            }
        });

        // Main thread: read driver messages and forward to worker thread
        // DIAGNOSTIC: Track which opcodes actually arrive from kernel
        let mut opcode_counts: [u64; 32] = [0; 32];
        let mut total_msgs: u64 = 0;
        let mut last_diag = std::time::Instant::now();
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let mut hyper_api_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let mut hyper_raw_counts: std::collections::HashMap<u32, u64> =
            std::collections::HashMap::new();

        loop {
            match driver.get_irp(&mut vecnew[..]) {
                Ok(Some(reply_irp)) => {
                    if reply_irp.num_ops > 0 {
                        let drivermsgs = CDriverMsgs::new(&reply_irp);
                        for drivermsg in drivermsgs {
                            let iomsg = IOMessage::from_driver_msg(&drivermsg);

                            // DIAGNOSTIC: Count by opcode
                            let op = iomsg.irp_op as usize;
                            if op < 32 {
                                opcode_counts[op] += 1;
                            }
                            total_msgs += 1;

                            // Log every event from the driver.
                            let irp = IrpMajorOp::from_byte(iomsg.irp_op);
                            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                            {
                                let hyper_event = iomsg.resolved_hypervisor_event();
                                let diag_irp = hyper_event
                                    .as_ref()
                                    .map(|event| event.irp_op.clone())
                                    .unwrap_or_else(|| irp.clone());
                                let raw_ty = hyper_event
                                    .as_ref()
                                    .map(|event| event.raw_event_type)
                                    .unwrap_or(iomsg.irp_op as u32);
                                let api_name = hyper_event
                                    .as_ref()
                                    .map(|event| event.event_name.clone())
                                    .filter(|name| !name.trim().is_empty())
                                    .unwrap_or_else(|| {
                                        let from_payload = iomsg.kernel_event_info.object_name.trim();
                                        if from_payload.is_empty() {
                                            iomsg.filepathstr.clone()
                                        } else {
                                            from_payload.to_string()
                                        }
                                    });
                                let is_hypervisor_event =
                                    matches!(diag_irp.clone(), IrpMajorOp::IrpHypervisorEvent);
                                let is_usermode_hook_event =
                                    matches!(diag_irp.clone(), IrpMajorOp::IrpUserModeHookEvent);
                                let is_kernel_telemetry_event = hyper_event.is_some()
                                    && !is_hypervisor_event
                                    && !is_usermode_hook_event;
                                let source_pid = hyper_event
                                    .as_ref()
                                    .map(|event| event.source_process_id)
                                    .unwrap_or(iomsg.pid);
                                let target_pid = hyper_event
                                    .as_ref()
                                    .map(|event| event.target_process_id)
                                    .unwrap_or(iomsg.pid);
                                let source_process = format_process_descriptor_with_fallback(
                                    source_pid,
                                    None,
                                );
                                let target_process = format_process_descriptor_with_fallback(
                                    target_pid,
                                    None,
                                );
                                let arg1 = hyper_event
                                    .as_ref()
                                    .map(|event| event.raw_argument1)
                                    .unwrap_or(iomsg.kernel_event_info.raw_argument1);
                                let arg2 = hyper_event
                                    .as_ref()
                                    .map(|event| event.raw_argument2)
                                    .unwrap_or(iomsg.kernel_event_info.raw_argument2);
                                let arg3 = hyper_event
                                    .as_ref()
                                    .map(|event| event.raw_argument3)
                                    .unwrap_or(iomsg.kernel_event_info.raw_argument3);
                                let arg4 = hyper_event
                                    .as_ref()
                                    .map(|event| event.raw_argument4)
                                    .unwrap_or(iomsg.kernel_event_info.raw_argument4);
                                let memory_address = hyper_event
                                    .as_ref()
                                    .map(|event| event.memory_address)
                                    .unwrap_or(iomsg.kernel_event_info.memory_address);
                                let memory_size = hyper_event
                                    .as_ref()
                                    .map(|event| event.memory_size)
                                    .unwrap_or(iomsg.kernel_event_info.memory_size as u64);
                                let operation_status = hyper_event
                                    .as_ref()
                                    .map(|event| event.operation_status)
                                    .unwrap_or(iomsg.kernel_event_info.operation_status);
                                let core_id = hyper_event
                                    .as_ref()
                                    .map(|event| event.core_id)
                                    .unwrap_or(iomsg.kernel_event_info.core_id);
                                let thread_id = hyper_event
                                    .as_ref()
                                    .map(|event| event.thread_id)
                                    .unwrap_or(iomsg.kernel_event_info.thread_id);
                                let context = hyper_event
                                    .as_ref()
                                    .map(|event| event.context)
                                    .unwrap_or(iomsg.kernel_event_info.context);

                                if is_usermode_hook_event {
                                    Logging::info(&format!(
                                        "[DIAG] USERMODE HOOK EVENT: op={:?} opcode={} raw_event_type={} gid={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} addr=0x{:X} size={} status=0x{:08X} api=\"{}\" cmd=\"{}\"",
                                        diag_irp,
                                        op,
                                        raw_ty,
                                        iomsg.gid,
                                        core_id,
                                        thread_id,
                                        context,
                                        source_process,
                                        target_process,
                                        arg1,
                                        arg2,
                                        arg3,
                                        arg4,
                                        memory_address,
                                        memory_size,
                                        operation_status as u32,
                                        api_name,
                                        iomsg.runtime_features.command_line
                                    ));
                                } else if is_hypervisor_event {
                                    *hyper_api_counts.entry(api_name.clone()).or_insert(0) += 1;
                                    *hyper_raw_counts.entry(raw_ty).or_insert(0) += 1;
                                    Logging::info(&format!(
                                        "[DIAG] VMM HOOK EVENT: op={:?} opcode={} raw_event_type={} gid={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} addr=0x{:X} size={} status=0x{:08X} api=\"{}\" cmd=\"{}\"",
                                        diag_irp,
                                        op,
                                        raw_ty,
                                        iomsg.gid,
                                        core_id,
                                        thread_id,
                                        context,
                                        source_process,
                                        target_process,
                                        arg1,
                                        arg2,
                                        arg3,
                                        arg4,
                                        memory_address,
                                        memory_size,
                                        operation_status as u32,
                                        api_name,
                                        iomsg.runtime_features.command_line
                                    ));
                                } else if is_kernel_telemetry_event {
                                    Logging::info(&format!(
                                        "[DIAG] KERNEL EVENT: op={:?} opcode={} raw_event_type={} gid={} core_id={} thread_id={} context=0x{:X} src_pid_path={} target_pid_path={} arg1=0x{:X} arg2=0x{:X} arg3=0x{:X} arg4=0x{:X} addr=0x{:X} size={} status=0x{:08X} event=\"{}\" cmd=\"{}\"",
                                        diag_irp,
                                        op,
                                        raw_ty,
                                        iomsg.gid,
                                        core_id,
                                        thread_id,
                                        context,
                                        source_process,
                                        target_process,
                                        arg1,
                                        arg2,
                                        arg3,
                                        arg4,
                                        memory_address,
                                        memory_size,
                                        operation_status as u32,
                                        api_name,
                                        iomsg.runtime_features.command_line
                                    ));
                                } else {
                                    Logging::info(&format!(
                                        "[DIAG] EVENT RECEIVED: op={:?} opcode={} pid={} gid={} path={} cmd=\"{}\"",
                                        irp,
                                        op,
                                        iomsg.pid,
                                        iomsg.gid,
                                        &iomsg.filepathstr,
                                        iomsg.runtime_features.command_line
                                    ));
                                }
                            }

                            #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                            Logging::info(&format!(
                                "[DIAG] EVENT RECEIVED: op={:?} opcode={} pid={} gid={} path={} cmd=\"{}\"",
                                irp,
                                op,
                                iomsg.pid,
                                iomsg.gid,
                                &iomsg.filepathstr,
                                iomsg.runtime_features.command_line
                            ));

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
                    Logging::error(&format!(
                        "Driver communication error (HRESULT: 0x{:X})",
                        e.code().0
                    ));
                    thread::sleep(std::time::Duration::from_millis(100));
                }
            }

            // DIAGNOSTIC: Print opcode distribution every 10 seconds
            if last_diag.elapsed() >= std::time::Duration::from_secs(10) {
                let mut summary = format!("[DIAG] {} total msgs in 10s. Opcodes: ", total_msgs);
                let names = [
                    "None",
                    "Read",
                    "Write",
                    "SetInfo",
                    "Create",
                    "Cleanup",
                    "Registry",
                    "ProcCreate",
                    "ProcTerm",
                    "ProcTermAttempt",
                    "ProcExit",
                    "ProcHandleOpen",
                ];
                for i in 0..12 {
                    if opcode_counts[i] > 0 {
                        summary.push_str(&format!("{}={} ", names[i], opcode_counts[i]));
                    }
                }
                let hypervisor_total = opcode_counts[12];
                let kernel_telemetry_total: u64 = opcode_counts.iter().skip(13).sum::<u64>();
                if hypervisor_total > 0 {
                    summary.push_str(&format!("ApiHooking={} ", hypervisor_total));
                }
                if kernel_telemetry_total > 0 {
                    summary.push_str(&format!("KernelTelemetry={} ", kernel_telemetry_total));
                }
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                if hypervisor_total > 0 {
                    let mut top_raw: Vec<(u32, u64)> =
                        hyper_raw_counts.iter().map(|(k, v)| (*k, *v)).collect();
                    top_raw.sort_by(|a, b| b.1.cmp(&a.1));
                    if !top_raw.is_empty() {
                        let raw_text = top_raw
                            .iter()
                            .take(5)
                            .map(|(raw, count)| format!("{}={}", raw, count))
                            .collect::<Vec<_>>()
                            .join(",");
                        summary.push_str(&format!("RawTop=[{}] ", raw_text));
                    }

                    let mut top_api: Vec<(String, u64)> = hyper_api_counts
                        .iter()
                        .map(|(k, v)| (k.clone(), *v))
                        .collect();
                    top_api.sort_by(|a, b| b.1.cmp(&a.1));
                    if !top_api.is_empty() {
                        let api_text = top_api
                            .iter()
                            .take(5)
                            .map(|(api, count)| format!("{}={}", api, count))
                            .collect::<Vec<_>>()
                            .join(",");
                        summary.push_str(&format!("ApiTop=[{}] ", api_text));
                    }
                }
                Logging::info(&summary);

                // Check specifically for the API-hooking opcode stream.
                if hypervisor_total == 0 {
                    Logging::warning(
                        "[DIAG] ZERO API HOOKING EVENTS (opcode 12) received from driver!",
                    );
                }

                opcode_counts = [0; 32];
                total_msgs = 0;
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    hyper_api_counts.clear();
                    hyper_raw_counts.clear();
                }
                last_diag = std::time::Instant::now();
            }
        }
    }
}
