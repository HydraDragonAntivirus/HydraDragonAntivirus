pub mod predictor {
    use crate::config::Config;
    use crate::predictions::prediction::input_tensors::Timestep;
    use crate::predictions::prediction::input_tensors::VecvecCappedF32;
    use crate::predictions::prediction::{PREDMTRXCOLS, PREDMTRXROWS};
    use crate::predictions::prediction_malware::TfLiteMalware;
    use crate::predictions::prediction_static::TfLiteStatic;
    use crate::predictions::xgboost::score;
    use crate::process::ProcessRecord;

    pub trait PredictorHandler {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32>;
    }

    pub trait PredictorHandlerBehavioral: PredictorHandler {
        fn is_prediction_required(
            &self,
            _threshold_drivermsgs: usize,
            _predictions_count: usize,
            _precord: &ProcessRecord,
        ) -> bool {
            // ALWAYS TRUE: Evaluates every single event immediately.
            // No more waiting for message counts or thresholds.
            true
        }
    }

    pub struct PredictionhandlerBehavioralXGBoost<'a> {
        config: &'a Config,
        predictions_count: usize,
    }

    impl PredictorHandlerBehavioral for PredictionhandlerBehavioralXGBoost<'_> {}

    impl PredictorHandler for PredictionhandlerBehavioralXGBoost<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            if self.is_prediction_required(
                self.config.threshold_drivermsgs,
                self.predictions_count,
                precord,
            ) {
                let timestep = Timestep::from(precord);
                self.predictions_count += 1;
                return Some(score(timestep.to_vec_f32())[1]);
            }
            None
        }
    }

    impl PredictionhandlerBehavioralXGBoost<'_> {
        pub fn new(config: &Config) -> PredictionhandlerBehavioralXGBoost<'_> {
            PredictionhandlerBehavioralXGBoost {
                config,
                predictions_count: 0,
            }
        }
    }

    pub struct PredictorHandlerBehavioralMLP<'a> {
        config: &'a Config,
        pub timesteps: VecvecCappedF32,
        predictions_count: usize,
        tflite_malware: TfLiteMalware,
    }

    impl PredictorHandlerBehavioral for PredictorHandlerBehavioralMLP<'_> {}

    impl PredictorHandler for PredictorHandlerBehavioralMLP<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            let timestep = Timestep::from(precord);
            self.timesteps.push_row(timestep.to_vec_f32()).unwrap();
            if self.timesteps.rows_len() > 0 {
                if self.is_prediction_required(
                    self.config.threshold_drivermsgs,
                    self.predictions_count,
                    precord,
                ) {
                    let prediction = self.tflite_malware.make_prediction(&self.timesteps);
                    return Some(prediction);
                }
                self.predictions_count += 1;
            }
            None
        }
    }

    impl PredictorHandlerBehavioralMLP<'_> {
        pub fn new(config: &Config) -> PredictorHandlerBehavioralMLP<'_> {
            PredictorHandlerBehavioralMLP {
                config,
                timesteps: VecvecCappedF32::new(PREDMTRXCOLS, PREDMTRXROWS),
                predictions_count: 0,
                tflite_malware: TfLiteMalware::new(config),
            }
        }
    }

    // Import LruCache for tracking
    use lru::LruCache;
    use std::num::NonZeroUsize;
    use std::path::PathBuf;

    pub struct PredictorHandlerStatic {
        predictor_static: TfLiteStatic,
        cache: LruCache<PathBuf, f32>,
    }

    impl PredictorHandler for PredictorHandlerStatic {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            if let Some(score) = self.cache.get(&precord.exepath) {
                return Some(*score);
            }
            
            if let Some(score) = self.predictor_static.make_prediction(&precord.exepath) {
                self.cache.push(precord.exepath.clone(), score);
                return Some(score);
            }
            
            None
        }
    }

    impl PredictorHandlerStatic {
        pub fn new(config: &Config) -> PredictorHandlerStatic {
            PredictorHandlerStatic {
                predictor_static: TfLiteStatic::new(config),
                cache: LruCache::new(NonZeroUsize::new(1000).unwrap()),
            }
        }
    }

    pub struct PredictorMalwareBehavioral<'a> {
        pub mlp: PredictorHandlerBehavioralMLP<'a>,
        pub xgboost: PredictionhandlerBehavioralXGBoost<'a>,
    }

    impl PredictorHandlerBehavioral for PredictorMalwareBehavioral<'_> {}

    impl PredictorHandler for PredictorMalwareBehavioral<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            self.xgboost.predict(precord)
        }
    }

    impl PredictorMalwareBehavioral<'_> {
        pub fn new(config: &Config) -> PredictorMalwareBehavioral<'_> {
            PredictorMalwareBehavioral {
                mlp: PredictorHandlerBehavioralMLP::new(config),
                xgboost: PredictionhandlerBehavioralXGBoost::new(config),
            }
        }
    }

    pub struct PredictorMalware<'a> {
        pub predictor_behavioral: PredictorMalwareBehavioral<'a>,
        pub predictor_static: PredictorHandlerStatic,
    }

    impl PredictorHandler for PredictorMalware<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            let opt_pred_b = self.predictor_behavioral.predict(precord);
            let opt_pred_s = self.predictor_static.predict(precord);

            match (opt_pred_s, opt_pred_b) {
                (Some(pred_s), Some(pred_b)) => {
                    Some(self.ponderate_prediction(precord, pred_s, pred_b))
                }
                (Some(pred_s), None) => Some(pred_s),
                (None, Some(pred_b)) => Some(pred_b),
                _ => None,
            }
        }
    }

    impl PredictorMalware<'_> {
        pub fn new(config: &Config) -> PredictorMalware<'_> {
            PredictorMalware {
                predictor_behavioral: PredictorMalwareBehavioral::new(config),
                predictor_static: PredictorHandlerStatic::new(config),
            }
        }

        fn ponderate_prediction(&self, precord: &ProcessRecord, pred_s: f32, pred_b: f32) -> f32 {
            let ponderation = match precord.driver_msg_count {
                0..=20 => 0.0,
                21..=50 => 0.5,
                _ => 0.8,
            };
            (1.0 - ponderation) * pred_s + ponderation * pred_b
        }
    }
}

pub mod process_record_handling {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    #[cfg(target_os = "windows")]
    use windows::Win32::Foundation::CloseHandle;
    #[cfg(target_os = "windows")]
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use chrono::Local;
    use lru::LruCache;

    use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
    use crate::config::{Config, KillPolicy, Param};
    use crate::csvwriter::CsvWriter;
    use crate::predictions::prediction::input_tensors::Timestep;
    use crate::process::{ProcessRecord, ProcessState};
    use crate::worker::predictor::{PredictorHandler, PredictorMalware};
    use crate::IOMessage;
    use crate::watchlist::WatchList;
    use crate::novelty::{Rule, StateSave};
    use crate::threat_handler::ThreatHandler;
    use crate::Logging;

    pub trait Exepath {
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf>;
    }

    #[derive(Default)]
    pub struct ExepathLive;

    impl Exepath for ExepathLive {
        #[cfg(target_os = "windows")]
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            let pid = iomsg.pid;
            unsafe {
                let r_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if let Ok(handle) = r_handle {
                    if !(handle.is_invalid() || handle.0 == 0) {
                        let mut buffer = vec![0u16; 1024];
                        let mut size = buffer.len() as u32;
                        let res = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buffer.as_mut_ptr()), &mut size);

                        CloseHandle(handle);
                        if res.as_bool() {
                            let path = String::from_utf16_lossy(&buffer[..size as usize]);
                            return Some(PathBuf::from(path));
                        }
                    }
                }
                None
            }
        }

        #[cfg(target_os = "linux")]
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            Some(iomsg.runtime_features.exepath.clone())
        }
    }

    #[derive(Default)]
    pub struct ExePathReplay;
    impl Exepath for ExePathReplay {
        fn exepath(&self, iomsg: &IOMessage) -> Option<PathBuf> {
            Some(iomsg.runtime_features.exepath.clone())
        }
    }

    pub trait ProcessRecordIOHandler {
        fn handle_io(&mut self, process_record: &mut ProcessRecord);
    }

    pub struct ProcessRecordHandlerLive<'a> {
        config: &'a Config,
        threat_handler: Box<dyn ThreatHandler>,
        predictor_malware: PredictorMalware<'a>,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerLive<'_> {
        #[cfg(target_os = "windows")]
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            // OPTIMIZATION: Don't re-process killed processes
            if precord.process_state == ProcessState::Killed {
                return;
            }

            if let Some(prediction_behavioral) = self.predictor_malware.predict(precord) {
                if prediction_behavioral > self.config.threshold_prediction
                    || precord.appname.contains("TEST-OLRANSOM")
                {
                    Logging::debug(&format!(
                        "MALWARE DETECTED - {} (gid: {}) | Prediction: {:.4} | Threshold: {:.4} | Files opened: {} | Files written: {} | Driver msgs: {}",
                        precord.appname, precord.gid,
                        prediction_behavioral, self.config.threshold_prediction,
                        precord.files_opened.len(), precord.files_written.len(), precord.driver_msg_count
                    ));
                    println!("Ransomware Suspected!!!");
                    eprintln!("precord.gid = {:?}", precord.gid);
                    println!("{}", precord.appname);
                    println!("with {prediction_behavioral} certainty");
                    println!(
                        "\nSee {}\\threats for details.",
                        self.config[Param::ProcessActivityLogPath]
                    );
                    println!(
                        "\nPlease update {}\\exclusions.txt if it's a false positive",
                        self.config[Param::ConfigPath]
                    );

                    // Handle based on kill policy
                    match self.config.get_kill_policy() {
                        KillPolicy::Suspend => {
                            if precord.process_state != ProcessState::Suspended {
                                self.threat_handler.suspend(precord);
                            }
                        }
                        KillPolicy::Kill => {
                            // Use kill_and_quarantine for Owlyshield's own detections
                            self.threat_handler.kill_and_quarantine(precord.gid, &precord.exepath);
                            precord.process_state = ProcessState::Killed;
                        }
                        KillPolicy::DoNothing => {}
                    }

                    // Create threat info for reporting
                    let threat_info = ThreatInfo {
                        threat_type_label: "Ransomware",
                        virus_name: "Behavioral Detection",     
                        prediction: prediction_behavioral,
                        match_details: None,
                        terminate: true,
                        kill_and_remove: true,
                        quarantine: true,
                        revert: true,
                    };
                    
                    // Run post-kill actions (logging, reporting, notifications)
                    ActionsOnKill::new().run_actions_with_info(
                        self.config,
                        precord,
                        &self.predictor_malware.predictor_behavioral.mlp.timesteps,
                        &threat_info,
                    );
                }
            }
        }

        #[cfg(target_os = "linux")]
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            // OPTIMIZATION: Don't re-process killed processes
            if precord.process_state == ProcessState::Killed {
                return;
            }

            if let Some(prediction_behavioral) = self.predictor_malware.predict(precord) {
                if prediction_behavioral > self.config.threshold_prediction
                    || precord.appname.contains("TEST-OLRANSOM")
                {
                    Logging::debug(&format!(
                        "MALWARE DETECTED - {} (gid: {}) | Prediction: {:.4} | Threshold: {:.4} | Files opened: {} | Files written: {} | Driver msgs: {}",
                        precord.appname, precord.gid,
                        prediction_behavioral, self.config.threshold_prediction,
                        precord.files_opened.len(), precord.files_written.len(), precord.driver_msg_count
                    ));
                    println!("Ransomware Suspected!!!");
                    eprintln!("precord.gid = {:?}", precord.gid);
                    println!("{}", precord.appname);
                    println!("with {} certainty", prediction_behavioral);
                    println!(
                        "\nSee {}\\threats for details.",
                        self.config[Param::ProcessActivityLogPath]
                    );
                    println!(
                        "\nPlease update {}\\exclusions.txt if it's a false positive",
                        self.config[Param::ConfigPath]
                    );

                    let threat_info = ThreatInfo {
                        threat_type_label: "Ransomware",
                        virus_name: "Behavioral Detection",
                        prediction: prediction_behavioral,
                        match_details: None,
                        terminate: true,
                        quarantine: true,
                        revert: true,
                    };

                    ActionsOnKill::with_handler(self.threat_handler.clone_box()).run_actions_with_info(
                        self.config,
                        precord,
                        &self.predictor_malware.predictor_behavioral.mlp.timesteps,
                        &threat_info,
                    );
                }
            }
        }
    }

    impl<'a> ProcessRecordHandlerLive<'a> {
        pub fn new(
            config: &'a Config,
            threat_handler: Box<dyn ThreatHandler>
        ) -> ProcessRecordHandlerLive<'a> {
            ProcessRecordHandlerLive {
                config,
                threat_handler,
                predictor_malware: PredictorMalware::new(config),
            }
        }
    }

    pub struct ProcessRecordHandlerReplay {
        csvwriter: CsvWriter,
        timesteps_stride: usize,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerReplay {
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            let timestep = Timestep::from(precord);
            if precord.driver_msg_count % self.timesteps_stride == 0 {
                thread::sleep(Duration::from_millis(2));
                self.csvwriter
                    .write_debug_csv_files(&precord.appname, precord.gid, &timestep, precord.time)
                    .expect("Cannot write csv learn file");
            }
        }
    }

    impl ProcessRecordHandlerReplay {
        pub fn new(config: &Config) -> ProcessRecordHandlerReplay {
            ProcessRecordHandlerReplay {
                csvwriter: CsvWriter::from(config),
                timesteps_stride: config.timesteps_stride,
            }
        }
    }

    pub struct ProcessRecordHandlerNovelty<'a> {
        config: &'a Config,
        watchlist: WatchList,
        rules: LruCache<String, Rule>,
    }

    impl ProcessRecordIOHandler for ProcessRecordHandlerNovelty<'_> {
        fn handle_io(&mut self, precord: &mut ProcessRecord) {
            if precord.driver_msg_count % 5 == 0 {
                if self.watchlist.is_app_watchlisted(precord.appname.as_str()) {
                    let novelty_path = self.config[Param::NoveltyPath].as_str();
                    let app_file = &precord.appname.replace(".", "_");
                    let now = Local::now();
                    let mut rule;

                    match self.rules.get(app_file) {
                        Some(r) => {
                            rule = r.to_owned();
                        },
                        None => {
                            let path = PathBuf::from(novelty_path).join(app_file.to_string() + ".yml");
                            if Rule::get_files(novelty_path).contains(app_file) {
                                rule = Rule::deserialize_yml_file(path);
                                let pathsave = PathBuf::from(novelty_path).join(app_file.to_string() + "_save.json");
                                let savestate = StateSave::load_file(&pathsave).unwrap();
                                savestate.update_precord(precord);
                            } else {
                                rule = Rule::from(precord);
                                Rule::serialize_yml_file(path, rule.clone());
                            }
                            self.rules.push(app_file.to_string(), rule.clone());
                        },
                    }
                    
                    if precord.driver_msg_count % 50 == 0 {
                        let mut newrule = rule.learn(precord);
                        if !newrule.is_clusters_empty() {
                            let dis = rule.distance(&newrule, precord);
                            let opt_clusterdistance_min = dis.iter().min_by(|cd1, cd2| cd1.distance.partial_cmp(&cd2.distance).unwrap_or(std::cmp::Ordering::Equal));

                            newrule.replace_subclusters(&rule, &dis);
                            if let Some(clusterdistance_min) = opt_clusterdistance_min {
                                if clusterdistance_min.distance > 0f32 {
                                    if clusterdistance_min.distance == 1f32 {
                                        Logging::novelty(&format!("[{}] New Cluster: {}", &precord.appname, clusterdistance_min.dir2.display()));
                                    } else {
                                        Logging::novelty(&format!("[{}] Expanding Cluster: {} => {}", &precord.appname, clusterdistance_min.dir1.display(), clusterdistance_min.dir2.display()));
                                    }
                                }
                            }

                            if now > (rule.update_time.unwrap_or_else(|| Local::now()) + chrono::Duration::minutes(20)) {
                                newrule.update_time = Some(now);
                                Rule::serialize_yml_file(PathBuf::from(novelty_path).join(app_file.to_string() + ".yml"), newrule.clone());
                                let savestate = StateSave::new(precord);
                                let pathsave = PathBuf::from(novelty_path).join(app_file.to_string() + "_save.json");
                                savestate.save_file(&pathsave).unwrap();
                            }
                            self.rules.put(app_file.to_string(), newrule);
                        }
                    }
                }
            }
        }
    }

    impl<'a> ProcessRecordHandlerNovelty<'a> {
        pub fn new(
            config: &'a Config,
            watchlist: WatchList,
        ) -> ProcessRecordHandlerNovelty<'a> {
            ProcessRecordHandlerNovelty {
                config,
                watchlist,
                rules: LruCache::new(std::num::NonZeroUsize::new(1024).unwrap()),
            }
        }
    }
}

mod process_records {
    use std::fs;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::time::{Duration, SystemTime};
    use lru::LruCache;
    use crate::config::{Config, Param};

    use crate::process::{ProcessRecord, ProcessState};
    use crate::threat_handler::ThreatHandler;

    pub struct ProcessRecords {
        pub process_records: LruCache<u64, ProcessRecord>,
    }

    impl ProcessRecords {
        pub fn new() -> ProcessRecords {
            ProcessRecords {
                process_records: LruCache::new(NonZeroUsize::new(10000).unwrap()),
            }
        }

        pub fn get_precord_by_gid(&mut self, gid: u64) -> Option<&ProcessRecord> {
            self.process_records.get(&gid)
        }

        pub fn get_precord_mut_by_gid(&mut self, gid: u64) -> Option<&mut ProcessRecord> {
            self.process_records.get_mut(&gid)
        }

        pub fn insert_precord(&mut self, gid: u64, precord: ProcessRecord) {
            self.process_records.push(gid, precord);
        }

        pub fn process_suspended_procs(&mut self, config: &Config, threat_handler: Box<dyn ThreatHandler>) {
            let now = SystemTime::now();
            for (gid, proc) in self.process_records.iter_mut() {
                if proc.process_state == ProcessState::Suspended {
                    if now.duration_since(proc.time_suspended.unwrap_or(now)).unwrap_or(Duration::from_secs(0)) > Duration::from_secs(120) {
                        threat_handler.awake(proc, true);
                        threat_handler.kill(*gid);
                    }
                }
            }

            let command_files_path = Path::new(&config[Param::ConfigPath]).join("tmp");
            if command_files_path.exists() {
                for command_file_dir_entry in fs::read_dir(command_files_path).unwrap() {
                    let pbuf_command_file = command_file_dir_entry.unwrap().path();
                    if pbuf_command_file.is_file() {
                        if let Some(ostr_fname) = pbuf_command_file.file_name() {
                            if let Some(fname) = ostr_fname.to_str() {
                                if let Some( (command, str_gid) ) = fname.split_once("_") {
                                    if let Ok(gid) = str_gid.parse::<u64>() {
                                        if let Some(proc) = self.process_records.get_mut(&gid) {
                                            match command {
                                                "A" => {
                                                    threat_handler.awake(proc, false);
                                                }
                                                "K" => {
                                                    threat_handler.awake(proc, true);
                                                    threat_handler.kill(gid);
                                                }
                                                &_ => {}
                                            }
                                            if !fs::remove_file(pbuf_command_file.as_path()).is_ok() {
                                                println!("cannot remove");
                                                eprintln!("pbuf_command_file = {:?}", pbuf_command_file);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub mod worker_instance {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{channel, Sender};
    use std::thread;
    use chrono::{DateTime, Utc};
    use log::error;
    use rumqtt::{MqttClient, MqttOptions, QoS};
    use crate::config::{Config, Param};
    use crate::csvwriter::CsvWriter;
    use crate::ExepathLive;
    use crate::process::ProcessRecord;
    use crate::whitelist::WhiteList;
    use crate::worker::process_record_handling::{
        ExePathReplay, Exepath, ProcessRecordHandlerReplay, ProcessRecordIOHandler,
    };
    use crate::worker::process_records::ProcessRecords;
    use crate::IOMessage;
    use crate::shared_def::IrpMajorOp;
    use crate::process::ProcessState;
    use crate::logging::Logging;
    use crate::jsonrpc::{Jsonrpc, RPCMessage};
    use crate::predictions::prediction::input_tensors::Timestep;
    use crate::threat_handler::ThreatHandler;
    use sysinfo::{System, ProcessesToUpdate, ProcessRefreshKind, Pid};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    #[cfg(feature = "realtime_learning")]
    use std::collections::HashMap;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::behavioral::behavior_engine::BehaviorEngine;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::behavioral::app_settings::AppSettings;
    #[cfg(feature = "realtime_learning")]
    use crate::realtime_learning::ApiTracker;

    pub trait IOMsgPostProcessor {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord);
    }

    pub struct IOMsgPostProcessorWriter {
        csv_writer: CsvWriter,
    }

    impl IOMsgPostProcessor for IOMsgPostProcessorWriter {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord) {
            iomsg.runtime_features.exepath = precord.exepath.clone();
            iomsg.runtime_features.exe_still_exists = true;
            let buf = rmp_serde::to_vec(&iomsg).unwrap();
            self.csv_writer
                .write_irp_csv_files(&buf)
                .expect("Cannot write irp file");
        }
    }

    impl IOMsgPostProcessorWriter {
        pub fn from(config: &Config) -> IOMsgPostProcessorWriter {
            let filename =
                &Path::new(&config[Param::ProcessActivityLogPath]).join(Path::new("drivermessages.txt"));
            IOMsgPostProcessorWriter {
                csv_writer: CsvWriter::from_path(filename),
            }
        }
    }

    pub struct IOMsgPostProcessorMqtt {
        pub client: Option<MqttClient>,
        channel: String,
    }

    impl IOMsgPostProcessorMqtt {
        pub fn new(mqtt_server: String) -> IOMsgPostProcessorMqtt {
            let mqtt_options = MqttOptions::new("iomsg", mqtt_server, 1883);
            let opt = MqttClient::start(mqtt_options).ok();
            let hostname = hostname::get()
                .unwrap()
                .to_str()
                .unwrap_or("Unknown host")
                .to_string();

            IOMsgPostProcessorMqtt {
                client: match opt {
                    None => {
                        println!("MQTT broker is not available. Ignoring it.");
                        error!("MQTT broker is not available. Ignoring it.");
                        None
                    }
                    Some( (client, _) ) => Some(client),
                },
                channel: String::from("data/") + &hostname,
            }
        }
    }

    impl IOMsgPostProcessor for IOMsgPostProcessorMqtt {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord) {
            if self.client.is_some() && precord.driver_msg_count % 250 == 0 {
                let mut c2 = self.client.as_ref().unwrap().clone();
                let channel = self.channel.clone();
                let vec = Timestep::from(precord).to_vec_f32();

                let datetime: DateTime<Utc> = iomsg.time.into();
                let mut process_vec = vec![String::from(&precord.appname), precord.gid.to_string(), datetime.timestamp_millis().to_string()];

                thread::spawn(move || {
                    process_vec.append(&mut vec.iter().map(|f| f.to_string()).collect::<Vec<String>>());
                    let csv = process_vec.join(",");
                    c2.publish(channel, QoS::ExactlyOnce, false, csv).unwrap();
                });
            }
        }
    }

    pub struct IOMsgPostProcessorRPC {
        tx: Sender<RPCMessage>,
    }

    impl IOMsgPostProcessor for IOMsgPostProcessorRPC {
        fn postprocess(&mut self, _iomsg: &mut IOMessage, precord: &ProcessRecord) {
            let timestep = Timestep::from(precord);
            let rpcmsg = RPCMessage::from(precord.appname.clone(), timestep);
            self.tx.send(rpcmsg).unwrap();
        }
    }

    impl IOMsgPostProcessorRPC {
        pub fn new() -> IOMsgPostProcessorRPC {
            let (tx, rx) = channel::<RPCMessage>();
            thread::spawn(move || {
                let mut jsonrpc = Jsonrpc::from(rx);
                jsonrpc.start_server();
            });
            IOMsgPostProcessorRPC {
                tx
            }
        }
    }

    pub struct Worker<'a> {
        whitelist: Option<&'a WhiteList>,
        process_records: ProcessRecords,
        process_record_handler: Option<Box<dyn ProcessRecordIOHandler + 'a>>,
        exepath_handler: Box<dyn Exepath>,
        iomsg_postprocessors: Vec<Box<dyn IOMsgPostProcessor>>,
        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        av_integration: Option<crate::av_integration::AVIntegration<'a>>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub behavior_engine: BehaviorEngine,
        #[cfg(feature = "realtime_learning")]
        pub learning_engine: crate::realtime_learning::RealtimeLearningEngine,
        #[cfg(feature = "realtime_learning")]
        pub api_trackers: HashMap<u64, ApiTracker>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub app_settings: AppSettings,
        pub threat_handler: Option<Box<dyn ThreatHandler>>,
    }

    impl<'a> Worker<'a> {
        pub fn new(config: &'a Config, #[cfg(all(target_os = "windows", feature = "behavior_engine"))] app_settings: AppSettings) -> Worker<'a> {
            Worker {
                whitelist: None,
                process_records: ProcessRecords::new(),
                process_record_handler: None,
                exepath_handler: Box::<ExepathLive>::default(),
                iomsg_postprocessors: vec![],
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                behavior_engine: BehaviorEngine::new(),
                #[cfg(feature = "realtime_learning")]
                learning_engine: {
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    let trust_path = Some(app_settings.win_verify_trust_path.to_str().unwrap());
                    #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                    let trust_path = None;
                    
                    crate::realtime_learning::RealtimeLearningEngine::new(config[Param::NoveltyPath].as_str(), trust_path)
                },
                #[cfg(feature = "realtime_learning")]
                api_trackers: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                app_settings,
                threat_handler: None,
            }
        }

        /// Discover pre-existing processes at startup (one-time only)
        /// This catches processes that were already running before the kernel driver loaded
        pub fn discover_existing_processes(&mut self) {
            Logging::info("[STARTUP] Discovering pre-existing processes (one-time scan)...");
            
            let mut sys = System::new_all();
            // FIX #1: Provide required arguments to refresh_processes
            sys.refresh_processes(ProcessesToUpdate::All, true);
            
            let mut discovered_count = 0;
            let mut skipped_count = 0;
            
            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                
                // Skip system process
                if pid_u32 == 4 {
                    continue;
                }
                
                let exepath = process.exe().map(|p| PathBuf::from(p)).unwrap_or_default();
                let appname = process.name().to_string_lossy().to_string();
                
                // Skip invalid paths
                if exepath.to_string_lossy().is_empty() || appname.is_empty() {
                    skipped_count += 1;
                    continue;
                }
                
                // Generate GID for this pre-existing process
                let gid = self.generate_gid_for_discovery(pid_u32, &exepath);
                
                // Check if kernel already notified us about this process
                if self.process_records.get_precord_by_gid(gid).is_some() {
                    continue;
                }
                
                // Create ProcessRecord for pre-existing process
                let precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                self.process_records.insert_precord(gid, precord);
                
                // Register in behavior engine
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    self.behavior_engine.register_process(
                        gid,
                        pid_u32,
                        exepath.clone(),
                        appname.clone()
                    );
                }
                
                discovered_count += 1;
                
                Logging::debug(&format!(
                    "[STARTUP] Pre-existing: {} (PID: {}, GID: {}, Path: {})",
                    appname, pid_u32, gid, exepath.display()
                ));
            }
            
            Logging::info(&format!(
                "[STARTUP] Discovery complete: {} processes registered, {} skipped",
                discovered_count, skipped_count
            ));
        }
        
        /// Generate GID for discovered processes
        /// NOTE: This must match your kernel's GID generation logic
        fn generate_gid_for_discovery(&self, pid: u32, exepath: &PathBuf) -> u64 {
            let mut hasher = DefaultHasher::new();
            pid.hash(&mut hasher);
            exepath.hash(&mut hasher);
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .hash(&mut hasher);
            hasher.finish()
        }

        pub fn whitelist(mut self, whitelist: &'a WhiteList) -> Worker<'a> {
            self.whitelist = Some(whitelist);
            self
        }

        pub fn process_record_handler(
            mut self,
            phandler: Box<dyn ProcessRecordIOHandler + 'a>,
        ) -> Worker<'a> {
            self.process_record_handler = Some(phandler);
            self
        }

        pub fn exepath_handler(mut self, exepath: Box<dyn Exepath>) -> Worker<'a> {
            self.exepath_handler = exepath;
            self
        }

        pub fn threat_handler(mut self, handler: Box<dyn ThreatHandler>) -> Worker<'a> {
            self.threat_handler = Some(handler);
            self
        }

        pub fn register_iomsg_postprocessor(
            mut self,
            postprecessor: Box<dyn IOMsgPostProcessor>,
        ) -> Worker<'a> {
            self.iomsg_postprocessors.push(postprecessor);
            self
        }

        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        #[allow(dead_code)]
        pub fn av_integration(mut self, av_integration: Option<crate::av_integration::AVIntegration<'a>>) -> Worker<'a> {
            self.av_integration = av_integration;
            self
        }

        pub fn build(self) -> Worker<'a> {
            self
        }

        /// Scan all tracked processes for behavioral detections
        pub fn scan_processes(&mut self, config: &Config, threat_handler: Box<dyn ThreatHandler>) {
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                // Import necessary Win32 modules for the Kernel Check
                use windows::Win32::System::Threading::{OpenProcess, GetExitCodeProcess, PROCESS_QUERY_LIMITED_INFORMATION};
                use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};

                // Refresh system state to identify new and dead processes
                // We keep sysinfo here because you requested Discovery logic to remain intact
                let mut sys = System::new_all();
                sys.refresh_processes(ProcessesToUpdate::All, true);
                
                // --- FIRST: Prune dead processes from behavior engine ---
                // IMPROVEMENT: We use direct Kernel Queries (OpenProcess) for 100% accuracy.
                let mut dead_gids = Vec::new();
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    unsafe {
                        let handle_res = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, state.pid);
                        match handle_res {
                            Ok(handle) => {
                                let mut exit_code: u32 = 0;
                                if GetExitCodeProcess(handle, &mut exit_code).as_bool() {
                                    if exit_code != STILL_ACTIVE.0 as u32 {
                                        dead_gids.push(*gid);
                                    }
                                }
                                let _ = CloseHandle(handle);
                            }
                            Err(_) => {
                                // Kernel says PID is invalid or gone
                                dead_gids.push(*gid);
                            }
                        }
                    }
                }

                if !dead_gids.is_empty() {
                    Logging::info(&format!("[BEHAVIOR SCAN] Pruning {} dead processes", dead_gids.len()));
                    for gid in dead_gids {
                        self.behavior_engine.process_states.remove(&gid);
                        self.process_records.process_records.pop(&gid);
                        #[cfg(feature = "realtime_learning")]
                        self.api_trackers.remove(&gid);
                    }
                }

                // --- SECOND: Discover any new processes that started since last scan ---
                let mut discovered_new = 0;
                for (pid, process) in sys.processes() {
                    let pid_u32 = pid.as_u32();
                    if pid_u32 == 4 { continue; } // Skip System
                    
                    let exepath = process.exe().map(|p| PathBuf::from(p)).unwrap_or_default();
                    let appname = process.name().to_string_lossy().to_string();
                    
                    if exepath.to_string_lossy().is_empty() || appname.is_empty() {
                        continue;
                    }
                    
                    let gid = self.generate_gid_for_discovery(pid_u32, &exepath);
                    let already_tracked_in_behavior = self.behavior_engine.process_states.contains_key(&gid);
                    let already_tracked_in_records = self.process_records.get_precord_by_gid(gid).is_some();
                    
                    if already_tracked_in_behavior || already_tracked_in_records {
                        continue;
                    }
                    
                    Logging::debug(&format!(
                        "[BEHAVIOR SCAN] Discovered new process during scan: {} (PID: {}, GID: {}, Path: {})",
                        appname, pid_u32, gid, exepath.display()
                    ));
                    
                    self.behavior_engine.register_process(gid, pid_u32, exepath.clone(), appname.clone());
                    let precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                    self.process_records.insert_precord(gid, precord);
                    discovered_new += 1;
                }
                
                if discovered_new > 0 {
                    Logging::info(&format!("[BEHAVIOR SCAN] Discovered {} new processes", discovered_new));
                }

                // --- THIRD: Sync behavior engine state to process_records ---
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    if self.process_records.get_precord_by_gid(*gid).is_none() {
                        let precord = ProcessRecord::new(*gid, state.app_name.clone(), state.exe_path.clone());
                        self.process_records.insert_precord(*gid, precord);
                        Logging::debug(&format!("[PROCESS SYNC] Registered GID: {} from behavior_engine", gid));
                    }
                }

                // Log Current Status
                let total_tracked = self.behavior_engine.process_states.len();
                if total_tracked > 0 {
                    Logging::info(&format!("[BEHAVIOR SCAN] Evaluating {} tracked processes", total_tracked));
                } else {
                    Logging::warning("[BEHAVIOR SCAN] No processes are being tracked!");
                }

                // --- FOURTH: Run the scan on all tracked processes ---
                let detections = self.behavior_engine.scan_all_processes(config, &*threat_handler);

                if !detections.is_empty() {
                    Logging::info(&format!("[BEHAVIOR SCAN] Found {} detections", detections.len()));
                }

                // --- FIFTH: Apply detections to process records ---
                for det in detections {
                    let matching_record = self.process_records.process_records
                        .iter_mut()
                        .find(|(gid, _)| **gid == det.gid);
                    
                    if let Some((_, record)) = matching_record {
                        record.is_malicious = true;
                        record.termination_requested = det.termination_requested;
                        record.quarantine_requested = det.quarantine_requested;
                        Logging::warning(&format!("[DETECTION] Process {} (GID: {}) marked malicious", record.appname, det.gid));
                        
                        // If termination is requested, execute via threat_handler
                        if det.termination_requested {
                            if let Some(state) = self.behavior_engine.process_states.get(&det.gid) {
                                threat_handler.kill(det.gid);
                            }
                        }
                    } else if let Some(state) = self.behavior_engine.process_states.get(&det.gid) {
                        // Handle detection for process not yet in records
                        let mut precord = ProcessRecord::new(det.gid, state.app_name.clone(), state.exe_path.clone());
                        precord.is_malicious = true;
                        precord.termination_requested = det.termination_requested;
                        precord.quarantine_requested = det.quarantine_requested;
                        self.process_records.insert_precord(det.gid, precord);
                        
                        if det.termination_requested {
                            threat_handler.kill(det.gid);
                        }
                    }
                }
            }
        }

        pub fn new_replay(config: &'a Config, whitelist: &'a WhiteList, #[cfg(all(target_os = "windows", feature = "behavior_engine"))] app_settings: AppSettings) -> Worker<'a> {
            Worker {
                whitelist: Some(whitelist),
                process_records: ProcessRecords::new(),
                process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
                exepath_handler: Box::<ExePathReplay>::default(),
                iomsg_postprocessors: vec![],
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                behavior_engine: BehaviorEngine::new(),
                #[cfg(feature = "realtime_learning")]
                learning_engine: {
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    let trust_path = Some(app_settings.win_verify_trust_path.to_str().unwrap());
                    #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                    let trust_path = None;
                    
                    crate::realtime_learning::RealtimeLearningEngine::new(config[Param::NoveltyPath].as_str(), trust_path)
                },
                #[cfg(feature = "realtime_learning")]
                api_trackers: HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                app_settings,
                threat_handler: None,
            }
        }

        /// Process kernel I/O event - this is the main event handler
        pub fn process_io(&mut self, iomsg: &mut IOMessage, config: &crate::config::Config) {
            let irp_op = IrpMajorOp::from_byte(iomsg.irp_op);
            let is_process_create = irp_op == IrpMajorOp::IrpProcessCreate;
            
            // Register or update process record based on kernel event
            self.register_precord(iomsg);
            let tracking_key = iomsg.gid;
            
            if let Some(precord) = self.process_records.get_precord_mut_by_gid(tracking_key) {
                // For new processes, run static scan immediately
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                if is_process_create {
                    if let Some(ref th) = self.threat_handler {
                        let detections = self.behavior_engine.scan_all_processes(config, &**th);
                        for det in detections {
                            if det.gid == tracking_key {
                                precord.is_malicious = true;
                                precord.termination_requested = det.termination_requested;
                                precord.quarantine_requested = det.quarantine_requested;
                                Logging::info(&format!(
                                    "[BEHAVIOR SCAN] Process {} (GID: {}, PID: {}) triggered detection on creation",
                                    precord.appname, precord.gid, iomsg.pid
                                ));
                                break;
                            }
                        }
                    }
                }
                
                // Add IRP record to process
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                {
                    if let Some(av_integration) = self.av_integration.as_mut() {
                        precord.add_irp_record(iomsg, Some(av_integration));
                    } else {
                        precord.add_irp_record(iomsg, None);
                    }
                }
                
                #[cfg(not(all(target_os = "windows", feature = "hydradragon")))]
                {
                    precord.add_irp_record(iomsg, None);
                }

                // Process behavioral event
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                if let Some(ref th) = self.threat_handler {
                    self.behavior_engine.process_event(precord, iomsg, config, &**th);
                }
                
                // Update learning engine
                #[cfg(feature = "realtime_learning")]
                {
                    self.learning_engine.update_activity(tracking_key);
                    if let Some(tracker) = self.api_trackers.get_mut(&tracking_key) {
                        tracker.track_io_operation(iomsg, precord);
                    }
                }

                // Run process record handler (e.g., prediction)
                if let Some(process_record_handler) = &mut self.process_record_handler {
                    process_record_handler.handle_io(precord);
                }

                // Handle process termination
                if irp_op == IrpMajorOp::IrpProcessTerminate {
                    precord.process_state = ProcessState::Terminated;
                    Logging::info(&format!("[KERNEL] Process Terminated: {} (GID: {}, PID: {})", 
                        precord.appname, precord.gid, iomsg.pid));
                }

                // Run postprocessors
                for postprocessor in &mut self.iomsg_postprocessors {
                    postprocessor.postprocess(iomsg, precord);
                }
            }

            // Cleanup on termination
            if irp_op == IrpMajorOp::IrpProcessTerminate {
                #[cfg(feature = "realtime_learning")]
                {
                    if let Some(precord) = self.process_records.process_records.pop(&tracking_key) {
                        if let Some(tracker) = self.api_trackers.remove(&tracking_key) {
                            self.learning_engine.process_terminated(tracking_key, &tracker, &precord);
                        }
                    }
                }
            }
        }

        pub fn process_suspended_records(&mut self, config: &Config, threat_handler: Box<dyn ThreatHandler>) {
            self.process_records.process_suspended_procs(config, threat_handler);

            #[cfg(feature = "realtime_learning")]
            {
                let mut terminated_gids = Vec::new();
                for (gid, proc) in self.process_records.process_records.iter() {
                    if proc.process_state == ProcessState::Terminated {
                        terminated_gids.push(*gid);
                    }
                }

                for gid in terminated_gids {
                    if let Some(precord) = self.process_records.process_records.pop(&gid) {
                        if let Some(tracker) = self.api_trackers.remove(&gid) {
                             self.learning_engine.process_terminated(gid, &tracker, &precord);
                        }
                    }
                }
            }
        }

        /// Register or update process record from kernel event
        /// This is the ONLY place where processes should be added to tracking
        fn register_precord(&mut self, iomsg: &mut IOMessage) {
            let gid = iomsg.gid;
            let pid = iomsg.pid;
            
            // FIX #2: Extract appname computation to avoid borrowing conflicts
            // Check if we need to upgrade or create
            let needs_action = match self.process_records.get_precord_by_gid(gid) {
                None => Some(true), // Need to create new
                Some(precord) => {
                    let needs_upgrade = precord.exepath.to_string_lossy() == "UNKNOWN" 
                        || precord.appname.starts_with("PROC_");
                    if needs_upgrade && !iomsg.filepathstr.is_empty() {
                        Some(false) // Need to upgrade existing
                    } else {
                        None // No action needed
                    }
                }
            };
            
            match needs_action {
                Some(true) => {
                    // New process - get info from kernel
                    let irp_op = IrpMajorOp::from_byte(iomsg.irp_op);
                    
                    let (exepath, appname) = if irp_op == IrpMajorOp::IrpProcessCreate 
                        && !iomsg.filepathstr.is_empty() {
                        // Process creation event with path from kernel
                        let path = PathBuf::from(&iomsg.filepathstr);
                        let name = Self::appname_from_exepath_static(&path)
                            .unwrap_or_else(|| format!("PROC_{}", pid));
                        (path, name)
                    } else {
                        // Non-creation event or missing path - query system
                        match self.exepath_handler.exepath(iomsg) {
                            Some(path) => {
                                let name = Self::appname_from_exepath_static(&path)
                                    .unwrap_or_else(|| format!("PROC_{}", pid));
                                (path, name)
                            }
                            None => {
                                // Kernel doesn't know about this process
                                Logging::warning(&format!(
                                    "[KERNEL] Unknown process PID {} GID {} - kernel may have missed creation event",
                                    pid, gid
                                ));
                                (PathBuf::from("UNKNOWN"), format!("PROC_{}", pid))
                            }
                        }
                    };

                    let log_type = if irp_op == IrpMajorOp::IrpProcessCreate {
                        "[PROCESS CREATE]"
                    } else {
                        "[KERNEL EVENT]"
                    };
                    
                    if appname.starts_with("PROC_") || exepath.to_string_lossy() == "UNKNOWN" {
                        Logging::warning(&format!("{} [UNRESOLVED] Process: {} (GID: {}, PID: {})", 
                            log_type, appname, gid, pid));
                    } else {
                        Logging::info(&format!("{} New Process: {} (GID: {}, PID: {}, Path: {})", 
                            log_type, appname, gid, pid, exepath.display()));
                    }

                    // Create process record
                    let precord = ProcessRecord::from(iomsg, appname.clone(), exepath.clone());
                    self.process_records.insert_precord(gid, precord);
                    
                    // Register in behavior engine
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    {
                        self.behavior_engine.register_process(
                            gid,
                            pid as u32,
                            exepath.clone(),
                            appname.clone()
                        );
                    }

                    // Register in learning engine
                    #[cfg(feature = "realtime_learning")]
                    {
                        self.learning_engine.track_process(gid, appname.clone());
                        self.api_trackers.insert(gid, ApiTracker::new(gid, appname));
                    }
                }
                Some(false) => {
                    // Existing process - upgrade UNKNOWN info
                    let path = PathBuf::from(&iomsg.filepathstr);
                    if let Some(name) = Self::appname_from_exepath_static(&path) {
                        // Get mutable reference after all immutable operations are done
                        if let Some(precord) = self.process_records.get_precord_mut_by_gid(gid) {
                            let old_name = precord.appname.clone();
                            
                            Logging::info(&format!(
                                "[KERNEL] Updated Process Info: {} -> {} (GID: {}, PID: {}, Path: {})",
                                old_name, name, gid, pid, path.display()
                            ));
                            
                            precord.exepath = path.clone();
                            precord.appname = name.clone();
                            
                            // Update behavior engine
                            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                            {
                                if let Some(state) = self.behavior_engine.process_states.get_mut(&gid) {
                                    state.exe_path = path;
                                    state.app_name = name;
                                }
                            }
                        }
                    }
                }
                None => {
                    // No action needed
                }
            }
        }

        fn appname_from_exepath(&self, exepath: &Path) -> Option<String> {
            Self::appname_from_exepath_static(exepath)
        }
        
        fn appname_from_exepath_static(exepath: &Path) -> Option<String> {
            exepath.file_name()?.to_str().map(|s| s.to_string())
        }
    }
}
