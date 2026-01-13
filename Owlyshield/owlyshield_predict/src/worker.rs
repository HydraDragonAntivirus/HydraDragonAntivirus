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
            threshold_drivermsgs: usize,
            _predictions_count: usize,
            precord: &ProcessRecord,
        ) -> bool {
            // Proactive scanning enabled
            precord.driver_msg_count % threshold_drivermsgs == 0
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

    use std::collections::HashMap;

    pub struct PredictorHandlerBehavioralMLP<'a> {
        config: &'a Config,
        pub timesteps: HashMap<u64, VecvecCappedF32>,
        predictions_count: usize,
        tflite_malware: TfLiteMalware,
    }

    impl PredictorHandlerBehavioral for PredictorHandlerBehavioralMLP<'_> {}

    impl PredictorHandler for PredictorHandlerBehavioralMLP<'_> {
        fn predict(&mut self, precord: &ProcessRecord) -> Option<f32> {
            let timestep = Timestep::from(precord);
            
            let timesteps = self.timesteps.entry(precord.gid).or_insert_with(|| {
                 VecvecCappedF32::new(PREDMTRXCOLS, PREDMTRXROWS)
            });

            timesteps.push_row(timestep.to_vec_f32()).unwrap();
            
            if timesteps.rows_len() > 0 {
                if self.is_prediction_required(
                    self.config.threshold_drivermsgs,
                    self.predictions_count,
                    precord,
                ) {
                    let prediction = self.tflite_malware.make_prediction(&timesteps);
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
                timesteps: HashMap::new(),
                predictions_count: 0,
                tflite_malware: TfLiteMalware::new(config),
            }
        }
    }

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
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
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
    use crate::worker::threat_handling::ThreatHandler;
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
                let r_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
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
        fn handle_behavior_detection(&mut self, process_record: &mut ProcessRecord);
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

        fn handle_behavior_detection(&mut self, precord: &mut ProcessRecord) {
            if precord.revert_requested {
                Logging::info(&format!("[BehaviorEngine] Reverting registry changes for: {}", precord.appname));
                self.threat_handler.revert_registry(precord.gid);
            }

            if precord.termination_requested {
                if precord.quarantine_requested {
                    Logging::info(&format!("[BehaviorEngine] Terminating and Quarantining: {}", precord.appname));
                    self.threat_handler.kill_and_quarantine(precord.gid, &precord.exepath);
                } else {
                    Logging::info(&format!("[BehaviorEngine] Terminating: {}", precord.appname));
                    self.threat_handler.kill(precord.gid);
                }
                precord.process_state = ProcessState::Killed;

                // Also run post-kill actions
                let threat_info = ThreatInfo {
                    threat_type_label: "Stealer/Malware",
                    virus_name: "Behavioral Rule Match",
                    prediction: 1.0, 
                };
                ActionsOnKill::new().run_actions_with_info(
                    self.config,
                    precord,
                    &self.predictor_malware.predictor_behavioral.mlp.timesteps,
                    &threat_info,
                );
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
                    };

                    ActionsOnKill::new().run_actions_with_info(
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

        fn handle_behavior_detection(&mut self, _precord: &mut ProcessRecord) {}
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

        fn handle_behavior_detection(&mut self, _precord: &mut ProcessRecord) {}
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
    use crate::worker::threat_handling::ThreatHandler;

    pub struct ProcessRecords {
        pub process_records: LruCache<u64, ProcessRecord>,
    }

    impl ProcessRecords {
        pub fn new() -> ProcessRecords {
            ProcessRecords {
                process_records: LruCache::new(NonZeroUsize::new(1024).unwrap()),
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

pub mod threat_handling {
    use std::path::Path;
    use crate::process::ProcessRecord;


    /// Trait for handling threat responses (kill, suspend, quarantine, etc.)
    pub trait ThreatHandler: Send + Sync {
        fn suspend(&self, proc: &mut ProcessRecord);
        fn kill(&self, gid: u64);
        fn kill_and_quarantine(&self, gid: u64, path: &Path);
        fn awake(&self, proc: &mut ProcessRecord, kill_proc_on_exit: bool);
        fn revert_registry(&self, gid: u64);
    }
}

pub mod worker_instance {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{channel, Sender};
    use std::thread;
    use chrono::{DateTime, Utc};
    use log::error;
    use rumqtt::{MqttClient, MqttOptions, QoS};
    // Import LruCache for tracking
    use lru::LruCache;
    use std::num::NonZeroUsize;

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
    use crate::jsonrpc::{Jsonrpc, RPCMessage};
    use crate::predictions::prediction::input_tensors::Timestep;
    use crate::worker::threat_handling::ThreatHandler;
    #[cfg(feature = "realtime_learning")]
    use crate::realtime_learning::api_tracker::ApiTracker;
    use crate::utils::is_process_alive;
    #[cfg(feature = "realtime_learning")]
    use std::collections::HashMap;

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
        // --- ADDED: Field to hold the AVIntegration instance ---
        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        av_integration: Option<crate::av_integration::AVIntegration<'a>>,
        pub behavior_engine: crate::behavior_engine::BehaviorEngine,
        #[cfg(feature = "realtime_learning")]
        pub learning_engine: crate::realtime_learning::RealtimeLearningEngine,
        #[cfg(feature = "realtime_learning")]
        pub api_trackers: HashMap<u64, ApiTracker>,
    }

    use crate::logging::Logging;

    impl<'a> Worker<'a> {
		pub fn new() -> Worker<'a> {
			Worker {
				whitelist: None,
				process_records: ProcessRecords::new(),
				process_record_handler: None,
				exepath_handler: Box::<ExepathLive>::default(),
				iomsg_postprocessors: vec![],
                // --- ADDED: Initialize new field ---
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                behavior_engine: crate::behavior_engine::BehaviorEngine::new(),
                #[cfg(feature = "realtime_learning")]
                learning_engine: crate::realtime_learning::RealtimeLearningEngine::new("."),
                #[cfg(feature = "realtime_learning")]
                api_trackers: std::collections::HashMap::new(),
			}
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



        pub fn register_iomsg_postprocessor(
            mut self,
            postprecessor: Box<dyn IOMsgPostProcessor>,
        ) -> Worker<'a> {
            self.iomsg_postprocessors.push(postprecessor);
            self
        }

        // --- ADDED: Builder method to set the AVIntegration instance ---
        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        #[allow(dead_code)] // Silencing warning, this builder method is used externally
        pub fn av_integration(mut self, av_integration: Option<crate::av_integration::AVIntegration<'a>>) -> Worker<'a> {
            self.av_integration = av_integration;
            self
        }

        pub fn build(self) -> Worker<'a> {
            self
        }

		pub fn new_replay(config: &'a Config, whitelist: &'a WhiteList) -> Worker<'a> {
			Worker {
				whitelist: Some(whitelist),
				process_records: ProcessRecords::new(),
				process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
				exepath_handler: Box::<ExePathReplay>::default(),
				iomsg_postprocessors: vec![],
                // --- ADDED: Initialize new field (None for replay) ---
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                behavior_engine: crate::behavior_engine::BehaviorEngine::new(),
                #[cfg(feature = "realtime_learning")]
                learning_engine: crate::realtime_learning::RealtimeLearningEngine::new("."),
                #[cfg(feature = "realtime_learning")]
                api_trackers: HashMap::new(),
			}
		}

        pub fn process_io(&mut self, iomsg: &mut IOMessage) {
            self.register_precord(iomsg);
            let tracking_key = iomsg.gid;
            if let Some(precord) = self.process_records.get_precord_mut_by_gid(tracking_key) {
                // Get AVIntegration from self if hydradragon feature is enabled
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                {
                    // --- MODIFIED: Use self.av_integration field ---
                    // This removes the need for the global static and fixes the import error.
                    if let Some(av_integration) = self.av_integration.as_mut() {
                        // Pass the mutable reference to AVIntegration
                        precord.add_irp_record(iomsg, Some(av_integration));
                    } else {
                        // No AVIntegration instance available
                        precord.add_irp_record(iomsg, None);
                    }
                }
                
                #[cfg(not(all(target_os = "windows", feature = "hydradragon")))]
                {
                    precord.add_irp_record(iomsg, None);
                }

                // --- ADDED: Process event in behavior engine ---
                self.behavior_engine.process_event(precord, iomsg);

                // --- ADDED: Update learning engine activity ---
                #[cfg(feature = "realtime_learning")]
                {
                    self.learning_engine.update_activity(tracking_key);
                    if let Some(tracker) = self.api_trackers.get_mut(&tracking_key) {
                        tracker.track_io_operation(iomsg, precord);
                    }
                }

                if let Some(process_record_handler) = &mut self.process_record_handler {
                    process_record_handler.handle_behavior_detection(precord);
                    process_record_handler.handle_io(precord);
                }
                for postprocessor in &mut self.iomsg_postprocessors {
                    postprocessor.postprocess(iomsg, precord);
                }
            }
        }

        pub fn process_suspended_records(&mut self, config: &Config, threat_handler: Box<dyn ThreatHandler>) {
            self.process_records.process_suspended_procs(config, threat_handler);

            // --- ADDED: Learn on Exit (Scan for terminated processes) ---
            #[cfg(feature = "realtime_learning")]
            {
                let mut terminated_gids = Vec::new();
                let now = std::time::SystemTime::now();

                // Check which processes are likely dead
                for (gid, proc) in self.process_records.process_records.iter() {
                    // Heuristic: If last message was > 10s ago and it's not a long-poll system process
                    let inactive_duration = now.duration_since(proc.time).unwrap_or(std::time::Duration::from_secs(0));
                    
                    if inactive_duration > std::time::Duration::from_secs(30) {
                        // Check if at least one PID in the family is still alive
                        let mut family_dead = true;
                        for pid in &proc.pids {
                            if is_process_alive(*pid) {
                                family_dead = false;
                                break;
                            }
                        }

                        if family_dead {
                            terminated_gids.push(*gid);
                        }
                    }
                }

                // Finalize learning for terminated processes
                for gid in terminated_gids {
                    if let Some(precord) = self.process_records.process_records.pop(&gid) {
                        if let Some(tracker) = self.api_trackers.remove(&gid) {
                             self.learning_engine.process_terminated(gid, &tracker, &precord);
                        }
                    }
                }
            }
        }

        fn register_precord(&mut self, iomsg: &mut IOMessage) {
            match self.process_records.get_precord_by_gid(iomsg.gid) {
                None => {
                    // SCANNING ISSUE FALLBACK: Try to get path, but don't drop if it fails
                    let exepath_opt = self.exepath_handler.exepath(iomsg);
                    let (exepath, appname): (PathBuf, String) = match exepath_opt {
                        Some(path) => {
                            let name = self.appname_from_exepath(&path).unwrap_or_else(|| String::from("DEFAULT"));
                            (path, name)
                        }
                        None => {
                            // Use PID as name if path unknown to ensure everything is "scanned"
                            (PathBuf::from("UNKNOWN"), format!("PROC_{}", iomsg.pid))
                        }
                    };

                    // LOGGING FIX: Log the scanned process immediately
                    Logging::info(&format!("[KERNEL SCAN] Scanned Process: {} (GID: {}, PID: {}, Path: {})", 
                        appname, iomsg.gid, iomsg.pid, exepath.display()));

                    let precord = ProcessRecord::from(iomsg, appname.clone(), exepath.clone());
                    self.process_records.insert_precord(iomsg.gid, precord);
                    
                    // Track in learning engine
                    #[cfg(feature = "realtime_learning")]
                    {
                        self.learning_engine.track_process(iomsg.gid, appname.clone());
                        self.api_trackers.insert(iomsg.gid, ApiTracker::new(iomsg.gid, appname));
                    }
                                           
                }
                Some(_) => {}
            }
        }



        fn appname_from_exepath(&self, exepath: &Path) -> Option<String> {
            exepath.to_str().map(|s| s.to_string())
        }
    }
}
