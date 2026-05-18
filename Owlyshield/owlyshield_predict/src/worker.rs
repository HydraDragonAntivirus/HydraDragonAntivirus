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

    pub struct PredictionHandlerBehavioralXGBoost<'a> {
        config: &'a Config,
        predictions_count: usize,
    }

    impl PredictorHandlerBehavioral for PredictionHandlerBehavioralXGBoost<'_> {}

    impl PredictorHandler for PredictionHandlerBehavioralXGBoost<'_> {
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

    impl PredictionHandlerBehavioralXGBoost<'_> {
        pub fn new(config: &Config) -> PredictionHandlerBehavioralXGBoost<'_> {
            PredictionHandlerBehavioralXGBoost {
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
        pub xgboost: PredictionHandlerBehavioralXGBoost<'a>,
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
                xgboost: PredictionHandlerBehavioralXGBoost::new(config),
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

    use chrono::Local;
    use lru::LruCache;
    #[cfg(target_os = "windows")]
    use windows::Win32::Foundation::CloseHandle;
    #[cfg(target_os = "windows")]
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    use super::predictor::PredictorMalware;
    use crate::IOMessage;
    use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};
    use crate::config::{Config, KillPolicy, Param};
    use crate::csvwriter::CsvWriter;
    use crate::logging::Logging;
    use crate::novelty::{Rule, StateSave};
    use crate::predictions::prediction::input_tensors::Timestep;
    use crate::process::{ProcessRecord, ProcessState};
    use crate::threat_handler::ThreatHandler;
    use crate::watchlist::WatchList;
    use crate::worker::predictor::PredictorHandler;

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
                if let Ok(handle) = r_handle
                    && !(handle.is_invalid() || handle.0 == 0)
                {
                    let mut buffer = vec![0u16; 1024];
                    let mut size = buffer.len() as u32;
                    let res = QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_WIN32,
                        windows::core::PWSTR(buffer.as_mut_ptr()),
                        &mut size,
                    );

                    CloseHandle(handle);
                    if res.as_bool() {
                        let path = String::from_utf16_lossy(&buffer[..size as usize]);
                        return Some(PathBuf::from(path));
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

            if let Some(prediction_behavioral) = self.predictor_malware.predict(precord)
                && (prediction_behavioral > self.config.threshold_prediction
                    || precord.appname.contains("TEST-OLRANSOM"))
            {
                Logging::debug(&format!(
                    "MALWARE DETECTED - {} (gid: {}) | Prediction: {:.4} | Threshold: {:.4} | Files opened: {} | Files written: {} | Driver msgs: {}",
                    precord.appname,
                    precord.gid,
                    prediction_behavioral,
                    self.config.threshold_prediction,
                    precord.files_opened.len(),
                    precord.files_written.len(),
                    precord.driver_msg_count
                ));
                println!("Ransomware Suspected!!!");
                eprintln!("precord.gid = {:?}", precord.gid);
                println!("{}", precord.appname);
                println!("with {prediction_behavioral} certainty");
                println!(
                    "\nSee {}\\threats for details.",
                    self.config[Param::RealTimeLearningPath]
                );
                println!("{}", self.config[Param::ConfigPath]);

                let kill_policy = self.config.get_kill_policy();
                let heuristic_hard_remediation = precord.appname.contains("TEST-OLRANSOM")
                    || (prediction_behavioral >= 0.98
                        && precord.driver_msg_count >= self.config.threshold_drivermsgs.max(120)
                        && (!precord.is_signed || !precord.has_valid_signature));

                if heuristic_hard_remediation
                    && matches!(kill_policy, KillPolicy::Suspend)
                    && precord.process_state != ProcessState::Suspended
                {
                    self.threat_handler.suspend(precord);
                }

                let threat_info = ThreatInfo {
                    threat_type_label: "Ransomware",
                    virus_name: "Behavioral Detection",
                    prediction: prediction_behavioral,
                    match_details: Some(if heuristic_hard_remediation {
                        "Heuristic malware detection reached hard-remediation threshold".to_string()
                    } else {
                        "Heuristic malware detection reached notify-only threshold; hard remediation withheld to avoid false-positive termination".to_string()
                    }),
                    deny_access: false,
                    terminate: heuristic_hard_remediation
                        && matches!(
                            kill_policy,
                            KillPolicy::Kill
                                | KillPolicy::KillAndQuarantine
                                | KillPolicy::KillAndRemove
                        ),
                    kill_and_remove: heuristic_hard_remediation
                        && matches!(kill_policy, KillPolicy::KillAndRemove),
                    quarantine: heuristic_hard_remediation
                        && matches!(kill_policy, KillPolicy::KillAndQuarantine),
                    suspend: heuristic_hard_remediation
                        && matches!(kill_policy, KillPolicy::Suspend),
                    notify_user: true,
                    revert: heuristic_hard_remediation,
                };

                if threat_info.terminate {
                    ActionsOnKill::with_handler(self.threat_handler.clone_box())
                        .run_actions_with_info(
                            self.config,
                            precord,
                            &self.predictor_malware.predictor_behavioral.mlp.timesteps,
                            &threat_info,
                        );
                } else {
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
                        precord.appname,
                        precord.gid,
                        prediction_behavioral,
                        self.config.threshold_prediction,
                        precord.files_opened.len(),
                        precord.files_written.len(),
                        precord.driver_msg_count
                    ));
                    println!("Ransomware Suspected!!!");
                    eprintln!("precord.gid = {:?}", precord.gid);
                    println!("{}", precord.appname);
                    println!("with {} certainty", prediction_behavioral);
                    println!(
                        "\nSee {}\\threats for details.",
                        self.config[Param::RealTimeLearningPath]
                    );
                    println!("{}", self.config[Param::ConfigPath]);

                    let threat_info = ThreatInfo {
                        threat_type_label: "Ransomware",
                        virus_name: "Behavioral Detection",
                        prediction: prediction_behavioral,
                        match_details: None,
                        deny_access: false,
                        terminate: true,
                        quarantine: true,
                        kill_and_remove: false,
                        suspend: false,
                        notify_user: true,
                        revert: true,
                    };

                    ActionsOnKill::with_handler(self.threat_handler.clone_box())
                        .run_actions_with_info(
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
            threat_handler: Box<dyn ThreatHandler>,
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
            if precord
                .driver_msg_count
                .is_multiple_of(self.timesteps_stride)
            {
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
            if precord.driver_msg_count.is_multiple_of(5)
                && self.watchlist.is_app_watchlisted(precord.appname.as_str())
            {
                let novelty_path = self.config[Param::NoveltyPath].as_str();
                let app_file = &precord.appname.replace(".", "_");
                let now = Local::now();
                let mut rule;

                match self.rules.get(app_file) {
                    Some(r) => {
                        rule = r.to_owned();
                    }
                    None => {
                        let path = PathBuf::from(novelty_path).join(app_file.to_string() + ".yml");
                        if Rule::get_files(novelty_path).contains(app_file) {
                            rule = Rule::deserialize_yml_file(path);
                            let pathsave = PathBuf::from(novelty_path)
                                .join(app_file.to_string() + "_save.json");
                            let savestate = StateSave::load_file(&pathsave).unwrap();
                            savestate.update_precord(precord);
                        } else {
                            rule = Rule::from(precord);
                            Rule::serialize_yml_file(path, rule.clone());
                        }
                        self.rules.push(app_file.to_string(), rule.clone());
                    }
                }

                if precord.driver_msg_count.is_multiple_of(50) {
                    let mut newrule = rule.learn(precord);
                    if !newrule.is_clusters_empty() {
                        let dis = rule.distance(&newrule, precord);
                        let opt_clusterdistance_min = dis.iter().min_by(|cd1, cd2| {
                            cd1.distance
                                .partial_cmp(&cd2.distance)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        });

                        newrule.replace_subclusters(&rule, &dis);
                        if let Some(clusterdistance_min) = opt_clusterdistance_min
                            && clusterdistance_min.distance > 0f32
                        {
                            if clusterdistance_min.distance == 1f32 {
                                Logging::novelty(&format!(
                                    "[{}] New Cluster: {}",
                                    &precord.appname,
                                    clusterdistance_min.dir2.display()
                                ));
                            } else {
                                Logging::novelty(&format!(
                                    "[{}] Expanding Cluster: {} => {}",
                                    &precord.appname,
                                    clusterdistance_min.dir1.display(),
                                    clusterdistance_min.dir2.display()
                                ));
                            }
                        }

                        if now
                            > (rule.update_time.unwrap_or_else(Local::now)
                                + chrono::Duration::minutes(20))
                        {
                            newrule.update_time = Some(now);
                            Rule::serialize_yml_file(
                                PathBuf::from(novelty_path).join(app_file.to_string() + ".yml"),
                                newrule.clone(),
                            );
                            let savestate = StateSave::new(precord);
                            let pathsave = PathBuf::from(novelty_path)
                                .join(app_file.to_string() + "_save.json");
                            savestate.save_file(&pathsave).unwrap();
                        }
                        self.rules.put(app_file.to_string(), newrule);
                    }
                }
            }
        }
    }

    impl<'a> ProcessRecordHandlerNovelty<'a> {
        pub fn new(config: &'a Config, watchlist: WatchList) -> ProcessRecordHandlerNovelty<'a> {
            ProcessRecordHandlerNovelty {
                config,
                watchlist,
                rules: LruCache::new(std::num::NonZeroUsize::new(1024).unwrap()),
            }
        }
    }
}

mod process_records {
    use crate::config::{Config, Param};
    use lru::LruCache;
    use std::fs;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use crate::logging::Logging;
    use crate::process::{ProcessRecord, ProcessState};
    use crate::threat_handler::ThreatHandler;
    use crate::utils::{
        protected_process_record_reason, suspicious_critical_process_record_reason,
    };

    pub struct ProcessRecords {
        pub process_records: LruCache<u64, ProcessRecord>,
        pub terminated_records: LruCache<u64, ProcessRecord>,
    }

    impl ProcessRecords {
        pub fn new() -> ProcessRecords {
            ProcessRecords {
                process_records: LruCache::new(NonZeroUsize::new(10000).unwrap()),
                terminated_records: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            }
        }

        pub fn get_precord_by_gid(&mut self, gid: u64) -> Option<&ProcessRecord> {
            self.process_records.get(&gid)
        }

        pub fn get_precord_by_gid_or_pid(&mut self, gid: u64, pid: u32) -> Option<&ProcessRecord> {
            if let Some((_, precord)) = self
                .process_records
                .iter()
                .find(|(candidate_gid, _)| **candidate_gid == gid)
            {
                return Some(precord);
            }

            self.process_records
                .iter()
                .find_map(|(_, precord)| precord.pids.contains(&pid).then_some(precord))
        }

        pub fn get_precord_mut_by_gid(&mut self, gid: u64) -> Option<&mut ProcessRecord> {
            self.process_records.get_mut(&gid)
        }

        pub fn insert_precord(&mut self, gid: u64, precord: ProcessRecord) {
            self.process_records.push(gid, precord);
        }

        pub fn process_suspended_procs(
            &mut self,
            config: &Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            let now = SystemTime::now();
            for (gid, proc) in self.process_records.iter_mut() {
                if proc.process_state == ProcessState::Suspended
                    && now
                        .duration_since(proc.time_suspended.unwrap_or(now))
                        .unwrap_or(Duration::from_secs(0))
                        > Duration::from_secs(120)
                {
                    if let Some(reason) = suspicious_critical_process_record_reason(proc) {
                        Logging::alert(&format!(
                            "[CriticalProcessAbuse] Refusing timed kill of suspicious critical-marked process {} (GID: {}): {}",
                            proc.appname, proc.gid, reason
                        ));
                        threat_handler.awake(proc, false);
                    } else if let Some(reason) = protected_process_record_reason(proc) {
                        Logging::warning(&format!(
                            "[ProcessRecords] Refusing timed kill of protected process {} (GID: {}): {}",
                            proc.appname, proc.gid, reason
                        ));
                        threat_handler.awake(proc, false);
                    } else {
                        threat_handler.awake(proc, true);
                        threat_handler.kill(*gid);
                    }
                }
            }

            let command_files_path = Path::new(&config[Param::ConfigPath]).join("tmp");
            if command_files_path.exists() {
                for command_file_dir_entry in fs::read_dir(command_files_path).unwrap() {
                    let pbuf_command_file = command_file_dir_entry.unwrap().path();
                    if pbuf_command_file.is_file()
                        && let Some(ostr_fname) = pbuf_command_file.file_name()
                        && let Some(fname) = ostr_fname.to_str()
                        && let Some((command, str_gid)) = fname.split_once("_")
                        && let Ok(gid) = str_gid.parse::<u64>()
                        && let Some(proc) = self.process_records.get_mut(&gid)
                    {
                        match command {
                            "A" => {
                                threat_handler.awake(proc, false);
                            }
                            "K" => {
                                if let Some(reason) =
                                    suspicious_critical_process_record_reason(proc)
                                {
                                    Logging::alert(&format!(
                                        "[CriticalProcessAbuse] Refusing manual kill of suspicious critical-marked process {} (GID: {}): {}",
                                        proc.appname, proc.gid, reason
                                    ));
                                    threat_handler.awake(proc, false);
                                } else if let Some(reason) = protected_process_record_reason(proc) {
                                    Logging::warning(&format!(
                                        "[ProcessRecords] Refusing manual kill of protected process {} (GID: {}): {}",
                                        proc.appname, proc.gid, reason
                                    ));
                                    threat_handler.awake(proc, false);
                                } else {
                                    threat_handler.awake(proc, true);
                                    threat_handler.kill(gid);
                                }
                            }
                            &_ => {}
                        }
                        if fs::remove_file(pbuf_command_file.as_path()).is_err() {
                            println!("cannot remove");
                            eprintln!("pbuf_command_file = {:?}", pbuf_command_file);
                        }
                    }
                }
            }
        }
    }
}

pub mod worker_instance {
    use crate::ExepathLive;
    use crate::IOMessage;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::actions_on_kill::{ActionsOnKill, ThreatInfo, restart_cleanup_reason};
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::behavioral::app_settings::AppSettings;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::behavioral::behavior_engine::BehaviorEngine;
    use crate::config::{Config, Param};
    use crate::csvwriter::CsvWriter;
    use crate::jsonrpc::{Jsonrpc, RPCMessage};
    use crate::logging::Logging;
    use crate::predictions::prediction::input_tensors::{Timestep, VecvecCappedF32};
    use crate::process::ProcessRecord;
    use crate::process::ProcessState;
    #[cfg(feature = "realtime_learning")]
    use crate::realtime_learning::ApiTracker;
    use crate::shared_def::IrpMajorOp;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::shared_def::effective_hypervisor_raw_event_type;
    use crate::threat_handler::ThreatHandler;
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use crate::utils::validate_pipe_client;
    use crate::worker::process_record_handling::{
        ExePathReplay, Exepath, ProcessRecordHandlerReplay, ProcessRecordIOHandler,
    };
    use crate::worker::process_records::ProcessRecords;
    use chrono::{DateTime, Utc};

    use rumqttc::{Client, MqttOptions, QoS};
    #[cfg(feature = "realtime_learning")]
    use std::collections::{HashMap, HashSet};
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Sender, channel};
    use std::thread;
    use sysinfo::{ProcessesToUpdate, System};
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
        PIPE_UNLIMITED_INSTANCES,
    };
    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    use windows::core::PCWSTR;

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
            let filename = &Path::new(&config[Param::RealTimeLearningPath])
                .join(Path::new("drivermessages.txt"));
            IOMsgPostProcessorWriter {
                csv_writer: CsvWriter::from_path(filename),
            }
        }
    }

    pub struct IOMsgPostProcessorMqtt {
        pub client: Option<Client>,
        channel: String,
    }

    impl IOMsgPostProcessorMqtt {
        pub fn new(mqtt_server: String) -> IOMsgPostProcessorMqtt {
            let mut mqtt_options = MqttOptions::new("iomsg", mqtt_server, 1883);
            mqtt_options.set_keep_alive(std::time::Duration::from_secs(5));

            let (client, mut connection) = Client::new(mqtt_options, 10);

            thread::spawn(move || {
                for _ in connection.iter() {
                    // Poll connection to keep it alive
                }
            });

            let hostname = hostname::get()
                .unwrap()
                .to_str()
                .unwrap_or("Unknown host")
                .to_string();

            IOMsgPostProcessorMqtt {
                client: Some(client),
                channel: String::from("data/") + &hostname,
            }
        }
    }

    impl IOMsgPostProcessor for IOMsgPostProcessorMqtt {
        fn postprocess(&mut self, iomsg: &mut IOMessage, precord: &ProcessRecord) {
            if let Some(client) = &self.client {
                if precord.driver_msg_count.is_multiple_of(250) {
                    let c2 = client.clone();
                    thread::spawn(move || {
                        let _ = c2.publish("owlyshield/heartbeat", QoS::AtMostOnce, false, "{}");
                    });
                }
                let channel = self.channel.clone();
                let vec = Timestep::from(precord).to_vec_f32();

                let datetime: DateTime<Utc> = iomsg.time.into();
                let mut process_vec = vec![
                    String::from(&precord.appname),
                    precord.gid.to_string(),
                    datetime.timestamp_millis().to_string(),
                ];

                let client_clone = client.clone();
                thread::spawn(move || {
                    process_vec
                        .append(&mut vec.iter().map(|f| f.to_string()).collect::<Vec<String>>());
                    let csv = process_vec.join(",");
                    let _ = client_clone.publish(channel, QoS::ExactlyOnce, false, csv);
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

    impl Default for IOMsgPostProcessorRPC {
        fn default() -> Self {
            Self::new()
        }
    }

    impl IOMsgPostProcessorRPC {
        pub fn new() -> IOMsgPostProcessorRPC {
            let (tx, rx) = channel::<RPCMessage>();
            thread::spawn(move || {
                let mut jsonrpc = Jsonrpc::from(rx);
                jsonrpc.start_server();
            });
            IOMsgPostProcessorRPC { tx }
        }
    }

    pub struct Worker<'a> {
        pub config: &'a Config,
        process_records: ProcessRecords,
        process_record_handler: Option<Box<dyn ProcessRecordIOHandler + 'a>>,
        exepath_handler: Box<dyn Exepath>,
        iomsg_postprocessors: Vec<Box<dyn IOMsgPostProcessor>>,
        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        av_integration: Option<crate::hydradragon::av_integration::AVIntegration<'a>>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub behavior_engine: BehaviorEngine,
        #[cfg(feature = "realtime_learning")]
        pub learning_engine: crate::realtime_learning::RealtimeLearningEngine,
        #[cfg(feature = "realtime_learning")]
        pub api_trackers: HashMap<u64, ApiTracker>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub app_settings: AppSettings,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hooks_registered: bool,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_event_map: std::collections::HashMap<u32, String>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_registered_apis: HashSet<String>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        next_dynamic_hook_event_id: u32,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_registration_blocked: bool,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_last_refresh: std::collections::HashMap<u32, std::time::Instant>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_target_generation: u64,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_applied_generation: std::collections::HashMap<u32, u64>,
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        dynamic_hook_apply_failures: std::collections::HashMap<u32, u32>,
        pub threat_handler: Option<Box<dyn ThreatHandler>>,
        #[cfg(target_os = "windows")]
        pub driver: Option<crate::Driver>,
        pub last_report_time: Option<std::time::Instant>,
    }

    impl<'a> Worker<'a> {
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub fn generate_system_report(&mut self) {
            let config = self.config;
            let _ = &config[crate::config::Param::ConfigPath]; // Explicit read to ensure compiler sees it as used
            let fw_pids = self.behavior_engine.firewall_net_pids.read().unwrap();
            let signatures_count = self.behavior_engine.rules.len();
            let rootkit_findings = self.behavior_engine.get_rootkit_findings();
            let mut report = crate::report::SystemReport::collect(
                config,
                Some(&fw_pids),
                signatures_count,
                rootkit_findings,
            );
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            let fw_net_details = self.behavior_engine.firewall_net_details.read().unwrap();

            // Collect process snapshots from behavior engine
            for (gid, state) in &self.behavior_engine.process_states {
                let mut path = state.exe_path.to_string_lossy().into_owned();
                if path.is_empty() || path == "UNKNOWN" {
                    if let Some(resolved) = crate::utils::resolve_process_path(state.pid) {
                        path = resolved.to_string_lossy().into_owned();
                    }
                }

                let fallback_directories_touched = state
                    .irp_stats
                    .unique_paths_accessed
                    .iter()
                    .filter_map(|value| {
                        let normalized = value.replace('\\', "/");
                        if !normalized.contains(":/") && !normalized.starts_with("//") {
                            return None;
                        }
                        Path::new(value)
                            .parent()
                            .map(|parent| parent.to_string_lossy().into_owned())
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();

                let fallback_files_updated = state
                    .irp_stats
                    .write_count
                    .saturating_add(state.irp_stats.setinfo_count)
                    .saturating_add(state.irp_stats.rename_count)
                    as usize;

                let mut snapshot = crate::report::ProcessSnapshot {
                    pid: state.pid,
                    gid: *gid as u32,
                    name: state.app_name.clone(),
                    path,
                    command_line: None,
                    process_state: "RUNNING".to_string(),
                    total_ops: state.irp_stats.get_total_operations(),
                    high_entropy_files: state.irp_stats.get_high_entropy_count(),
                    driver_message_count: state.irp_stats.get_total_operations() as usize,
                    ops_read: state.irp_stats.read_count,
                    ops_written: state.irp_stats.write_count,
                    ops_open: state.irp_stats.create_count,
                    ops_setinfo: state.irp_stats.setinfo_count,
                    bytes_read: state.irp_stats.total_bytes_read,
                    bytes_written: state.irp_stats.total_bytes_written,
                    files_created: state.irp_stats.create_count as usize,
                    files_updated: fallback_files_updated,
                    files_deleted: state.irp_stats.delete_count as usize,
                    directories_touched: fallback_directories_touched,
                    is_malicious: false,
                    detections: Vec::new(),
                    detection_details: None,
                    named_conditions: Vec::new(),
                    detected_apis: Vec::new(),
                    network_targets: Vec::new(),
                    rootkit_implicated: state.rootkit_implicated,
                    rootkit_findings: state
                        .rootkit_findings
                        .iter()
                        .take(12)
                        .map(|finding| {
                            format!(
                                "{} (addr=0x{:X}, pid={})",
                                finding.kind.threat_label(),
                                finding.address,
                                finding.pid
                            )
                        })
                        .collect(),
                    remediation_target: None,
                    signature_summary: if state.is_signed {
                        if state.has_valid_signature {
                            "Signed / Trusted".to_string()
                        } else {
                            "Signed / Untrusted".to_string()
                        }
                    } else {
                        "Unsigned or Unknown".to_string()
                    },
                    sample_created_paths: Vec::new(),
                    sample_updated_paths: Vec::new(),
                    restart_cleanup_requested: false,
                };

                if let Some(precord) = self
                    .process_records
                    .get_precord_by_gid_or_pid(*gid, state.pid)
                {
                    snapshot.is_malicious = precord.is_malicious;
                    snapshot.process_state = precord.process_state.to_string();
                    snapshot.driver_message_count = precord.driver_msg_count;
                    snapshot.ops_read = precord.ops_read;
                    snapshot.ops_written = precord.ops_written;
                    snapshot.ops_open = precord.ops_open;
                    snapshot.ops_setinfo = precord.ops_setinfo;
                    snapshot.bytes_read = precord.bytes_read;
                    snapshot.bytes_written = precord.bytes_written;
                    snapshot.files_created = precord.fpaths_created.len();
                    snapshot.files_updated = precord.fpaths_updated.len();
                    snapshot.files_deleted = precord.files_deleted.len();
                    let mut directories_touched = std::collections::BTreeSet::new();
                    directories_touched.extend(precord.dirs_with_files_created.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_updated.iter().cloned());
                    directories_touched.extend(precord.dirs_with_files_opened.iter().cloned());
                    snapshot.directories_touched = directories_touched.len();
                    if !precord.command_line.trim().is_empty() {
                        snapshot.command_line = Some(precord.command_line.clone());
                    }
                    if let Some(ref rule) = precord.triggered_rule_name {
                        snapshot.detections.push(rule.clone());
                    }
                    snapshot.detection_details = precord.triggered_rule_details.clone();
                    snapshot.remediation_target = precord
                        .remediation_target_path
                        .as_ref()
                        .map(|path| path.display().to_string());
                    let mut sample_created_paths =
                        precord.fpaths_created.iter().cloned().collect::<Vec<_>>();
                    sample_created_paths.sort();
                    sample_created_paths.truncate(6);
                    snapshot.sample_created_paths = sample_created_paths;
                    let mut sample_updated_paths =
                        precord.fpaths_updated.iter().cloned().collect::<Vec<_>>();
                    sample_updated_paths.sort();
                    sample_updated_paths.truncate(6);
                    snapshot.sample_updated_paths = sample_updated_paths;
                    snapshot.restart_cleanup_requested = precord.restart_cleanup_requested;
                }

                if snapshot.command_line.is_none() && !state.command_line.trim().is_empty() {
                    snapshot.command_line = Some(state.command_line.clone());
                }

                for cond in &state.satisfied_named_conditions {
                    snapshot.named_conditions.push(cond.clone());
                    snapshot.detections.push(format!("Condition: {}", cond));
                }

                snapshot.named_conditions.sort();
                snapshot.named_conditions.dedup();

                snapshot.detected_apis = state.detected_apis.iter().cloned().collect();
                snapshot.detected_apis.sort();
                snapshot.detected_apis.dedup();

                #[cfg(all(target_os = "windows", feature = "firewall"))]
                if let Some(targets) = fw_net_details.get(&state.pid) {
                    let mut network_targets = targets
                        .iter()
                        .map(|(ip, port)| format!("{}:{}", ip, port))
                        .collect::<Vec<_>>();
                    network_targets.sort();
                    network_targets.dedup();
                    network_targets.truncate(12);
                    snapshot.network_targets = network_targets;
                }

                if let Some(targets) = self
                    .behavior_engine
                    .openedr_net_details
                    .read()
                    .unwrap()
                    .get(&state.pid)
                {
                    let mut network_targets = snapshot.network_targets.clone();
                    network_targets
                        .extend(targets.iter().map(|(ip, port)| format!("{}:{}", ip, port)));
                    network_targets.sort();
                    network_targets.dedup();
                    network_targets.truncate(12);
                    snapshot.network_targets = network_targets;
                }

                snapshot.detections.sort();
                snapshot.detections.dedup();

                report.monitored_processes.push(snapshot);
            }

            match report.save_to_file() {
                Ok(path) => Logging::info(&format!(
                    "[REPORT] HijackThis-style system diagnostic report generated: {}",
                    path.display()
                )),
                Err(e) => Logging::error(&format!("[REPORT] Failed to save system report: {}", e)),
            }
            self.last_report_time = Some(std::time::Instant::now());
        }

        const PID_FALLBACK_GID_MASK: u64 = 0x8000_0000_0000_0000;
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        const DYNAMIC_HOOK_EVENT_ID_START: u32 = 0x6000;
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        const DYNAMIC_HOOK_MAX_FAILURES: u32 = 3;

        #[cfg(target_os = "windows")]
        fn is_internal_service_pid(pid: u32) -> bool {
            pid == std::process::id()
        }

        #[cfg(not(target_os = "windows"))]
        fn is_internal_service_pid(_pid: u32) -> bool {
            false
        }

        fn is_rootkit_irp(irp_op: &IrpMajorOp) -> bool {
            matches!(
                irp_op,
                IrpMajorOp::IrpRootkitSsdtHook
                    | IrpMajorOp::IrpRootkitHiddenProcess
                    | IrpMajorOp::IrpRootkitHiddenDriver
                    | IrpMajorOp::IrpRootkitKernelHook
                    | IrpMajorOp::IrpRootkitTerminateProcess
                    | IrpMajorOp::IrpRootkitFileMove
                    | IrpMajorOp::IrpRootkitGeneric
            )
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn is_unattributed_rootkit_event(iomsg: &IOMessage, irp_op: &IrpMajorOp) -> bool {
            Self::is_rootkit_irp(irp_op)
                && iomsg.gid == 0
                && iomsg.pid == 0
                && iomsg.attacker_pid == 0
                && iomsg.kernel_event_info.source_process_id == 0
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn build_behavior_engine(config: &Config) -> BehaviorEngine {
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            static FIREWALL_PIPE_START: std::sync::Once = std::sync::Once::new();
            #[cfg(all(target_os = "windows", feature = "sanctum"))]
            static SANCTUM_PIPE_START: std::sync::Once = std::sync::Once::new();
            static OPENEDR_PIPE_START: std::sync::Once = std::sync::Once::new();

            let extension_source_mode = config.extension_source_mode();
            let engine =
                BehaviorEngine::new_with_extension_source_mode(extension_source_mode.as_deref());
            #[cfg(all(target_os = "windows", feature = "firewall"))]
            FIREWALL_PIPE_START.call_once(|| {
                engine.start_firewall_pipe();
            });
            #[cfg(all(target_os = "windows", feature = "sanctum"))]
            SANCTUM_PIPE_START.call_once(|| {
                Self::start_sanctum_telemetry_pipe(engine.clone());
            });
            OPENEDR_PIPE_START.call_once({
                let engine = engine.clone();
                move || {
                    Self::start_openedr_telemetry_pipe(engine);
                }
            });
            engine
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        pub fn start_openedr_telemetry_pipe(behavior_engine: BehaviorEngine) {
            std::thread::Builder::new()
                .name("openedr_telemetry_pipe".to_string())
                .spawn(move || {
                    let pipe_name_str = r"\\.\pipe\Global\HydraDragonOpenEdrTelemetry";
                    let wide: Vec<u16> = OsStr::new(pipe_name_str)
                        .encode_wide()
                        .chain(std::iter::once(0u16))
                        .collect();

                    Logging::info("[OpenEDRTelemetry] Starting direct OpenEDR telemetry pipe");

                    loop {
                        let handle: HANDLE = unsafe {
                            CreateNamedPipeW(
                                PCWSTR(wide.as_ptr()),
                                PIPE_ACCESS_INBOUND,
                                NAMED_PIPE_MODE(0),
                                PIPE_UNLIMITED_INSTANCES,
                                0,
                                65536,
                                0,
                                None,
                            )
                        };

                        if handle == INVALID_HANDLE_VALUE {
                            Logging::error("[OpenEDRTelemetry] CreateNamedPipeW failed; retrying");
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            continue;
                        }

                        let connected = unsafe { ConnectNamedPipe(handle, None) }.as_bool()
                            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

                        if !connected {
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(250));
                            continue;
                        }

                        if !unsafe { validate_pipe_client(handle, Some(r"OpenEDR\edrsvc.exe"), false) } {
                            Logging::error("[OpenEDRTelemetry] Rejected unauthorized OpenEDR telemetry client");
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            continue;
                        }

                        let mut buf = vec![0u8; 65536];
                        let mut leftover = String::new();

                        loop {
                            let mut bytes_read: u32 = 0;
                            let ok = unsafe {
                                ReadFile(
                                    handle,
                                    Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                                    buf.len() as u32,
                                    Some(&mut bytes_read),
                                    None,
                                )
                            };
                            if !ok.as_bool() || bytes_read == 0 {
                                break;
                            }

                            leftover.push_str(&String::from_utf8_lossy(&buf[..bytes_read as usize]));
                            while let Some(pos) = leftover.find('\n') {
                                let line = leftover[..pos].trim().to_string();
                                leftover = leftover[pos + 1..].to_string();
                                if line.is_empty() {
                                    continue;
                                }

                                match serde_json::from_str::<serde_json::Value>(&line) {
                                    Ok(event) => behavior_engine.ingest_openedr_event(&event),
                                    Err(err) => Logging::warning(&format!(
                                        "[OpenEDRTelemetry] Failed to parse direct event JSON: {}",
                                        err
                                    )),
                                }
                            }
                        }

                        unsafe {
                            let _ = DisconnectNamedPipe(handle);
                            let _ = CloseHandle(handle);
                        }
                    }
                })
                .expect("failed to spawn openedr_telemetry_pipe thread");
        }

        /// Spawn the \\.\pipe\HydraSanctumTelemetry named pipe server thread.
        /// Moved to Worker.rs as requested (Starting + Detection handling).
        /// Other ingestion codes remain in BehaviorEngine::ingest_sanctum_event.
        #[cfg(all(
            target_os = "windows",
            feature = "behavior_engine",
            feature = "sanctum"
        ))]
        pub fn start_sanctum_telemetry_pipe(mut behavior_engine: BehaviorEngine) {
            std::thread::Builder::new()
                .name("sanctum_telemetry_pipe".to_string())
                .spawn(move || {
                    let pipe_name_str = r"\\.\pipe\HydraSanctumTelemetry";
                    let wide: Vec<u16> = OsStr::new(pipe_name_str)
                        .encode_wide()
                        .chain(std::iter::once(0u16))
                        .collect();

                    Logging::info("[SanctumPipe] Starting Sanctum telemetry pipe server (Worker Managed)");

                    loop {
                        let handle: HANDLE = unsafe {
                            CreateNamedPipeW(
                                PCWSTR(wide.as_ptr()),
                                PIPE_ACCESS_INBOUND,
                                NAMED_PIPE_MODE(0),
                                PIPE_UNLIMITED_INSTANCES,
                                0,
                                65536,
                                0,
                                None,
                            )
                        };

                        if handle == INVALID_HANDLE_VALUE {
                            Logging::error("[SanctumPipe] CreateNamedPipeW failed; retrying in 2s");
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            continue;
                        }

                        let connected = unsafe { ConnectNamedPipe(handle, None) }.as_bool()
                            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

                        if !connected {
                            Logging::warning("[SanctumPipe] ConnectNamedPipe failed; recreating pipe");
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(250));
                            continue;
                        }

                        // Validate: only accept Sanctum's um_engine with strict full-path validation
                        if !unsafe { validate_pipe_client(handle, Some(r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum\um_engine.exe"), false) } {
                            Logging::error("[SanctumPipe] Rejected unauthorized client (Strict Path Validation Failed)");
                            unsafe {
                                let _ = DisconnectNamedPipe(handle);
                                let _ = CloseHandle(handle);
                            }
                            continue;
                        }

                        Logging::info("[SanctumPipe] Sanctum um_engine connected");

                        let mut buf = vec![0u8; 65536];
                        let mut leftover = String::new();

                        loop {
                            let mut bytes_read: u32 = 0;
                            let ok = unsafe {
                                ReadFile(
                                    handle,
                                    Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                                    buf.len() as u32,
                                    Some(&mut bytes_read),
                                    None,
                                )
                            };
                            if !ok.as_bool() || bytes_read == 0 {
                                break;
                            }
                            leftover.push_str(&String::from_utf8_lossy(&buf[..bytes_read as usize]));

                            while let Some(pos) = leftover.find('\n') {
                                let line = leftover[..pos].trim().to_string();
                                leftover = leftover[pos + 1..].to_string();

                                if line.is_empty() {
                                    continue;
                                }

                                match serde_json::from_str::<serde_json::Value>(&line) {
                                    Ok(event) => {
                                        let pid = event["pid"].as_u64().unwrap_or(0) as u32;
                                        let source = event["source"].as_str().unwrap_or("-");
                                        let function = event["function"].as_str().unwrap_or("-");

                                        let is_detection = event["is_detection"].as_bool().unwrap_or(false)
                                            || event["type"] == "DETECTION"
                                            || event["function"] == "DETECTION"
                                            || source == "DETECTION";

                                        // 1. Telemetry Ingestion (Other codes) - handled by behavior engine
                                        behavior_engine.ingest_sanctum_event(&event);

                                        // 2. Detection Handling - moved to Worker level
                                        if is_detection {
                                            Logging::alert(&format!("[SanctumDetection] 🚨 ALERT: Sanctum EDR flagged PID {} for malicious activity ({}/{})", pid, source, function));
                                        }

                                        Logging::info(&format!(
                                            "[SanctumTele] pid={} src={} fn={}",
                                            pid, source, function
                                        ));
                                    }
                                    Err(e) => {
                                        Logging::warning(&format!(
                                            "[SanctumPipe] Failed to parse event JSON: {}",
                                            e
                                        ));
                                    }
                                }
                            }
                        }

                        Logging::info("[SanctumPipe] Sanctum um_engine disconnected; waiting for reconnect");
                        unsafe {
                            let _ = DisconnectNamedPipe(handle);
                            let _ = CloseHandle(handle);
                        }
                    }
                })
                .expect("failed to spawn sanctum_telemetry_pipe thread");
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        #[allow(dead_code)]
        fn apply_behavior_detection_state(record: &mut ProcessRecord, det: &ProcessRecord) {
            record.is_malicious = true;
            record.termination_requested = det.termination_requested;
            record.quarantine_requested = det.quarantine_requested;
            record.deny_access_requested = det.deny_access_requested;
            record.kill_and_remove_requested = det.kill_and_remove_requested;
            record.notify_user_requested = det.notify_user_requested;
            record.revert_requested = det.revert_requested;
            record.restart_cleanup_requested = det.restart_cleanup_requested;
            record.triggered_rule_name = det.triggered_rule_name.clone();
            record.triggered_rule_details = det.triggered_rule_details.clone();
            record.remediation_target_path = det.remediation_target_path.clone();
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        #[allow(dead_code)]
        fn build_behavior_threat_info<'b>(det: &'b ProcessRecord, context: &str) -> ThreatInfo<'b> {
            let mut virus_name = det
                .triggered_rule_name
                .as_deref()
                .unwrap_or("Behavioral Detection");
            let mut legacy_details = None;

            if let Some(encoded) = det.triggered_rule_name.as_deref()
                && let Some(rest) = encoded.strip_prefix("FirewallNetworkBlock|")
            {
                let mut parts = rest.splitn(2, '|');
                if let Some(label) = parts.next()
                    && !label.trim().is_empty()
                {
                    virus_name = label;
                }
                if let Some(details) = parts.next()
                    && !details.trim().is_empty()
                {
                    legacy_details = Some(details.to_string());
                }
            }

            let match_details = det
                .triggered_rule_details
                .clone()
                .or(legacy_details)
                .or_else(|| match &det.triggered_rule_name {
                    Some(rule_name) => match det.remediation_target_path.as_ref() {
                        Some(path) => Some(format!(
                            "Rule '{}' matched during {}. Target: {}",
                            rule_name,
                            context,
                            path.display()
                        )),
                        None => Some(format!("Rule '{}' matched during {}", rule_name, context)),
                    },
                    None => match det.remediation_target_path.as_ref() {
                        Some(path) => Some(format!(
                            "Behavioral detection matched during {}. Target: {}",
                            context,
                            path.display()
                        )),
                        None => Some(format!("Behavioral detection matched during {}", context)),
                    },
                });

            ThreatInfo {
                threat_type_label: "Behavioral Detection",
                virus_name,
                prediction: 1.0,
                match_details,
                deny_access: det.deny_access_requested,
                terminate: det.termination_requested,
                quarantine: det.quarantine_requested,
                kill_and_remove: det.kill_and_remove_requested,
                suspend: det.suspend_requested,
                notify_user: det.notify_user_requested,
                revert: det.revert_requested,
            }
        }

        #[cfg(feature = "realtime_learning")]
        fn realtime_learning_output_dir(config: &Config) -> &str {
            if let Some(path) = config.get_param(Param::RealTimeLearningPath) {
                return path;
            }

            "./ml_data/realtime"
        }

        #[cfg(feature = "realtime_learning")]
        fn record_realtime_event(
            learning_engine: &mut crate::realtime_learning::RealtimeLearningEngine,
            api_trackers: &mut HashMap<u64, ApiTracker>,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            behavior_engine: &crate::behavioral::behavior_engine::BehaviorEngine,
            gid: u64,
            iomsg: &IOMessage,
            precord: &ProcessRecord,
        ) {
            learning_engine.update_activity(gid);

            let tracker = api_trackers
                .entry(gid)
                .or_insert_with(|| ApiTracker::new(gid, precord.appname.clone()));

            if !precord.appname.is_empty() && tracker.process_name != precord.appname {
                tracker.process_name = precord.appname.clone();
            }

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                if let Some(state) = behavior_engine.process_states.get(&gid) {
                    #[cfg(all(target_os = "windows", feature = "firewall"))]
                    {
                        tracker.net_packets = state.net_packets.clone().into();
                    }
                    #[cfg(all(target_os = "windows", feature = "sanctum"))]
                    {
                        tracker.sanctum_operations = state.sanctum_stats.clone();
                    }
                }
            }

            tracker.track_io_operation(iomsg, precord);
        }

        #[cfg(feature = "realtime_learning")]
        fn mark_realtime_process_malicious(
            learning_engine: &mut crate::realtime_learning::RealtimeLearningEngine,
            api_trackers: &HashMap<u64, ApiTracker>,
            gid: u64,
            precord: &ProcessRecord,
        ) {
            learning_engine.track_process(gid, precord.appname.clone());

            if let Some(tracker) = api_trackers.get(&gid) {
                learning_engine.mark_detected_malicious(gid, tracker, precord);
            }
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn default_dynamic_hook_event_map() -> std::collections::HashMap<u32, String> {
            std::collections::HashMap::new()
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn default_registered_dynamic_apis() -> HashSet<String> {
            HashSet::new()
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn should_refresh_dynamic_hooks_for_pid(&mut self, pid: u32) -> bool {
            if pid == 0 {
                return false;
            }

            let now = std::time::Instant::now();
            let refresh_interval = std::time::Duration::from_secs(2);

            if let Some(last) = self.dynamic_hook_last_refresh.get(&pid)
                && now.duration_since(*last) < refresh_interval
            {
                return false;
            }

            self.dynamic_hook_last_refresh.insert(pid, now);
            true
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn refresh_dynamic_hooks_for_pid_if_due(&mut self, pid: u32) {
            if Self::should_skip_dynamic_hooks_for_pid(pid) {
                return;
            }

            if self.should_refresh_dynamic_hooks_for_pid(pid) {
                self.register_dynamic_hooks_for_process(pid);
            }
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn should_skip_dynamic_hooks_for_pid(pid: u32) -> bool {
            if pid == 0 || Self::is_internal_service_pid(pid) {
                return true;
            }

            crate::utils::protected_process_reason(pid, None).is_some()
        }

        /// Normalize unstable kernel GIDs to keep per-process tracking coherent.
        /// 1) gid=0 => PID-scoped synthetic GID.
        /// 2) If PID is already known under another GID, re-use that GID.
        /// 3) If an incoming GID is already owned by a different PID, remap to synthetic PID GID.
        fn normalize_tracking_gid(&self, iomsg: &mut IOMessage) {
            let pid = if iomsg.pid != 0 {
                iomsg.pid
            } else {
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    iomsg.attacker_pid
                }
                #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                {
                    0
                }
            };
            if pid == 0 {
                return;
            }

            if iomsg.gid == 0 {
                iomsg.gid = Self::PID_FALLBACK_GID_MASK | (pid as u64);
                return;
            }

            if let Some(existing_gid_for_pid) = self.find_gid_by_pid(pid) {
                if existing_gid_for_pid != iomsg.gid {
                    Logging::warning(&format!(
                        "[GID RESOLVE] PID {} remapped from kernel GID {} to tracked GID {}",
                        pid, iomsg.gid, existing_gid_for_pid
                    ));
                    iomsg.gid = existing_gid_for_pid;
                }
                return;
            }

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            let behavior_pid_conflict = self
                .behavior_engine
                .process_states
                .get(&iomsg.gid)
                .map(|s| s.pid != 0 && s.pid != pid)
                .unwrap_or(false);

            #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
            let behavior_pid_conflict = false;

            let record_pid_conflict = self
                .process_records
                .process_records
                .peek(&iomsg.gid)
                .map(|p| !p.pids.is_empty() && !p.pids.contains(&pid))
                .unwrap_or(false);

            if behavior_pid_conflict || record_pid_conflict {
                let remapped = Self::PID_FALLBACK_GID_MASK | (pid as u64);
                Logging::warning(&format!(
                    "[GID COLLISION] PID {} kernel GID {} collides with existing tracked process; using synthetic GID {}",
                    pid, iomsg.gid, remapped
                ));
                iomsg.gid = remapped;
            }
        }
        pub fn new(
            config: &'a Config,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            app_settings: AppSettings,
        ) -> Self {
            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: None,
                exepath_handler: Box::<ExepathLive>::default(),
                threat_handler: None,
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                app_settings: app_settings.clone(),
                iomsg_postprocessors: vec![],
                #[cfg(feature = "realtime_learning")]
                api_trackers: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                behavior_engine: Self::build_behavior_engine(config),
                #[cfg(feature = "realtime_learning")]
                learning_engine: {
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    let trust_path = Some(app_settings.win_verify_trust_path.to_str().unwrap());
                    #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                    let trust_path = None;

                    crate::realtime_learning::RealtimeLearningEngine::new(
                        Self::realtime_learning_output_dir(config),
                        trust_path,
                    )
                },
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hooks_registered: false,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_registered_apis: Self::default_registered_dynamic_apis(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_registration_blocked: false,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_last_refresh: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_target_generation: 0,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_applied_generation: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_apply_failures: std::collections::HashMap::new(),
                #[cfg(target_os = "windows")]
                driver: None,
                last_report_time: None,
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
                if pid_u32 == 4 || Self::is_internal_service_pid(pid_u32) {
                    continue;
                }

                let exepath = process.exe().map(PathBuf::from).unwrap_or_default();
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
                        appname.clone(),
                    );
                    self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                }

                discovered_count += 1;

                Logging::debug(&format!(
                    "[STARTUP] Pre-existing: {} (PID: {}, GID: {}, Path: {})",
                    appname,
                    pid_u32,
                    gid,
                    exepath.display()
                ));
            }

            Logging::info(&format!(
                "[STARTUP] Discovery complete: {} processes registered, {} skipped",
                discovered_count, skipped_count
            ));
        }

        /// Generate a PID-backed synthetic GID for user-mode discovered processes.
        /// This keeps tracking stable and lets the driver action path fall back to PID.
        fn generate_gid_for_discovery(&self, pid: u32, _exepath: &PathBuf) -> u64 {
            Self::PID_FALLBACK_GID_MASK | (pid as u64)
        }

        /// Find GID by PID - needed because kernel GIDs and discovery GIDs may not match
        /// Returns the GID if we're already tracking this PID
        fn find_gid_by_pid(&self, pid: u32) -> Option<u64> {
            // Check behavior engine first (most likely location)
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                for (gid, state) in &self.behavior_engine.process_states {
                    if state.pid == pid {
                        return Some(*gid);
                    }
                }
            }

            // Fallback: check process_records (in case behavior_engine not enabled)
            for (gid, precord) in &self.process_records.process_records {
                // Check if this precord contains the PID
                if precord.pids.contains(&pid) {
                    return Some(*gid);
                }
            }

            None
        }

        #[cfg(all(
            target_os = "windows",
            feature = "behavior_engine",
            feature = "firewall"
        ))]
        fn sync_firewall_process_contexts(&mut self) {
            let firewall_pids: Vec<u32> = self
                .behavior_engine
                .firewall_net_pids
                .read()
                .unwrap()
                .iter()
                .copied()
                .collect();
            let mut stale_pids = Vec::new();

            for pid in firewall_pids {
                if pid == 0 || Self::is_internal_service_pid(pid) {
                    continue;
                }

                let Some(exepath) = crate::utils::resolve_process_path(pid) else {
                    if !crate::utils::is_process_alive(pid) {
                        stale_pids.push(pid);
                    }
                    continue;
                };

                let appname = Self::appname_from_exepath_static(&exepath)
                    .unwrap_or_else(|| format!("PROC_{}", pid));
                let gid = self
                    .find_gid_by_pid(pid)
                    .unwrap_or(Self::PID_FALLBACK_GID_MASK | (pid as u64));
                let is_new_record = self.process_records.get_precord_by_gid(gid).is_none();

                self.behavior_engine
                    .register_process(gid, pid, exepath.clone(), appname.clone());

                if let Some(precord) = self.process_records.get_precord_mut_by_gid(gid) {
                    precord.pids.insert(pid);
                    if precord.exepath.as_os_str().is_empty()
                        || precord.exepath.to_string_lossy() == "UNKNOWN"
                    {
                        precord.exepath = exepath.clone();
                    }
                    if precord.appname.is_empty()
                        || precord.appname.starts_with("PROC_")
                        || precord.appname == "UNKNOWN"
                    {
                        precord.appname = appname.clone();
                    }
                } else {
                    let mut precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                    precord.pids.insert(pid);
                    self.process_records.insert_precord(gid, precord);

                    #[cfg(feature = "realtime_learning")]
                    {
                        self.learning_engine.track_process(gid, appname.clone());
                        self.api_trackers
                            .entry(gid)
                            .or_insert_with(|| ApiTracker::new(gid, appname.clone()));
                    }
                }

                self.refresh_dynamic_hooks_for_pid_if_due(pid);

                if is_new_record {
                    Logging::info(&format!(
                        "[HydraNetPipe] Registered firewall-observed PID {} as tracked worker process {} (GID: {})",
                        pid,
                        exepath.display(),
                        gid
                    ));
                }
            }

            if !stale_pids.is_empty() {
                let mut firewall_pids = self.behavior_engine.firewall_net_pids.write().unwrap();
                for pid in stale_pids {
                    firewall_pids.remove(&pid);
                }
            }
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

        #[cfg(target_os = "windows")]
        pub fn driver(mut self, driver: crate::Driver) -> Worker<'a> {
            #[cfg(target_os = "windows")]
            crate::driver_com::register_shared_driver(driver.clone());
            self.driver = Some(driver);
            self
        }

        pub fn register_iomsg_postprocessor(
            mut self,
            postprocessor: Box<dyn IOMsgPostProcessor>,
        ) -> Worker<'a> {
            self.iomsg_postprocessors.push(postprocessor);
            self
        }

        #[cfg(all(target_os = "windows", feature = "hydradragon"))]
        #[allow(dead_code)]
        pub fn av_integration(
            mut self,
            av_integration: Option<crate::hydradragon::av_integration::AVIntegration<'a>>,
        ) -> Worker<'a> {
            self.av_integration = av_integration;
            self
        }

        pub fn build(self) -> Worker<'a> {
            self
        }

        /// Validate all tracked processes and remove any with dead PIDs
        /// This is a safety net to catch processes tracked with mismatched GIDs
        pub fn validate_tracked_processes(&mut self) {
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
                use windows::Win32::System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };

                let mut dead_gids = Vec::new();
                let mut total_checked = 0;

                // Check all tracked processes in behavior engine
                for (gid, state) in &self.behavior_engine.process_states {
                    total_checked += 1;
                    let pid = state.pid;
                    let mut is_dead = false;

                    unsafe {
                        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                            Ok(handle) => {
                                let mut exit_code: u32 = 0;
                                if GetExitCodeProcess(handle, &mut exit_code).as_bool()
                                    && exit_code != STILL_ACTIVE.0 as u32
                                {
                                    is_dead = true;
                                }
                                let _ = CloseHandle(handle);
                            }
                            Err(_) => {
                                // Process handle invalid - definitely dead
                                is_dead = true;
                            }
                        }
                    }

                    if is_dead {
                        dead_gids.push(*gid);
                    }
                }

                if !dead_gids.is_empty() {
                    Logging::info(&format!(
                        "[VALIDATION] Cleaning {} dead processes (checked {} total)",
                        dead_gids.len(),
                        total_checked
                    ));

                    for gid in dead_gids {
                        self.cleanup_process(gid, "Dead (validation)");
                    }
                } else if total_checked > 0 {
                    Logging::debug(&format!(
                        "[VALIDATION] All {} tracked processes are alive",
                        total_checked
                    ));
                }
            }
        }

        /// Centralized cleanup function for removing process from all tracking structures
        fn cleanup_process(&mut self, gid: u64, reason: &str) {
            // Get process info before removal for logging
            let process_info = self
                .process_records
                .get_precord_by_gid(gid)
                .map(|p| (p.appname.clone(), p.exepath.clone()));

            // Remove from process_records
            let precord_opt = self.process_records.process_records.pop(&gid);

            if let Some(mut precord) = precord_opt {
                precord.process_state = ProcessState::Terminated;

                #[cfg(feature = "realtime_learning")]
                {
                    let tracker = self
                        .api_trackers
                        .entry(gid)
                        .or_insert_with(|| ApiTracker::new(gid, precord.appname.clone()));
                    tracker.is_terminated = true;
                    tracker.termination_time = Some(std::time::SystemTime::now());
                }

                // Remove from behavior engine
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                {
                    self.behavior_engine.process_states.remove(&gid);
                    #[cfg(all(target_os = "windows", feature = "firewall"))]
                    {
                        let mut firewall_pids =
                            self.behavior_engine.firewall_net_pids.write().unwrap();
                        for pid in &precord.pids {
                            firewall_pids.remove(pid);
                        }
                    }
                    for pid in &precord.pids {
                        self.dynamic_hook_last_refresh.remove(pid);
                        self.dynamic_hook_applied_generation.remove(pid);
                        self.dynamic_hook_apply_failures.remove(pid);
                    }
                }

                // Handle learning engine cleanup
                #[cfg(feature = "realtime_learning")]
                {
                    if precord.is_malicious {
                        self.learning_engine.mark_detected_malicious(
                            gid,
                            self.api_trackers.get(&gid).unwrap(),
                            &precord,
                        );
                    }
                    if let Some(tracker) = self.api_trackers.remove(&gid) {
                        self.learning_engine
                            .process_terminated(gid, &tracker, &precord);
                    }
                }

                // Keep terminated history out of the active tracking map so the same
                // dead process cannot be "cleaned up" over and over again.
                self.process_records.terminated_records.push(gid, precord);
            }

            // Log cleanup
            if let Some((appname, exepath)) = process_info {
                Logging::info(&format!(
                    "[CLEANUP] {} removed: {} (GID: {}, Path: {})",
                    reason,
                    appname,
                    gid,
                    exepath.display()
                ));
            } else {
                Logging::debug(&format!("[CLEANUP] {} removed GID: {}", reason, gid));
            }
        }

        /// Scan all tracked processes for behavioral detections
        pub fn scan_processes(
            &mut self,
            #[cfg_attr(
                not(all(target_os = "windows", feature = "behavior_engine")),
                allow(unused_variables)
            )]
            config: &Config,
            #[cfg_attr(
                not(all(target_os = "windows", feature = "behavior_engine")),
                allow(unused_variables)
            )]
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                // Import necessary Win32 modules for the Kernel Check
                use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
                use windows::Win32::System::Threading::{
                    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };

                // Refresh system state to identify new and dead processes
                // We keep sysinfo here because you requested Discovery logic to remain intact
                let mut sys = System::new_all();
                sys.refresh_processes(ProcessesToUpdate::All, true);

                // --- FIRST: Prune dead processes from behavior engine ---
                // IMPROVEMENT: We use direct Kernel Queries (OpenProcess) for 100% accuracy.
                let mut dead_gids = Vec::new();
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    unsafe {
                        let handle_res =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, state.pid);
                        match handle_res {
                            Ok(handle) => {
                                let mut exit_code: u32 = 0;
                                if GetExitCodeProcess(handle, &mut exit_code).as_bool()
                                    && exit_code != STILL_ACTIVE.0 as u32
                                {
                                    dead_gids.push(*gid);
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

                // FIX: Use centralized cleanup function
                if !dead_gids.is_empty() {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Pruning {} dead processes",
                        dead_gids.len()
                    ));
                    for gid in dead_gids {
                        self.cleanup_process(gid, "Dead process");
                    }
                }

                // --- SECOND: Discover any new processes that started since last scan ---
                let mut discovered_new = 0;
                for (pid, process) in sys.processes() {
                    let pid_u32 = pid.as_u32();
                    if pid_u32 == 4 || Self::is_internal_service_pid(pid_u32) {
                        continue;
                    }

                    let exepath = process.exe().map(PathBuf::from).unwrap_or_default();
                    let appname = process.name().to_string_lossy().to_string();

                    if exepath.to_string_lossy().is_empty() || appname.is_empty() {
                        continue;
                    }

                    // FIX: Check if we're ALREADY tracking this PID
                    // This prevents duplicate entries when GID generation is non-deterministic
                    if self.find_gid_by_pid(pid_u32).is_some() {
                        self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);
                        // Already tracking this PID - skip to avoid duplicates
                        continue;
                    }

                    // Generate a new GID for this discovered process
                    // NOTE: This may not match the kernel's GID, but we use PID lookup
                    // to prevent duplicates regardless
                    let gid = self.generate_gid_for_discovery(pid_u32, &exepath);

                    Logging::debug(&format!(
                        "[BEHAVIOR SCAN] Discovered new process during scan: {} (PID: {}, GID: {}, Path: {})",
                        appname,
                        pid_u32,
                        gid,
                        exepath.display()
                    ));

                    self.behavior_engine.register_process(
                        gid,
                        pid_u32,
                        exepath.clone(),
                        appname.clone(),
                    );
                    let precord = ProcessRecord::new(gid, appname.clone(), exepath.clone());
                    self.process_records.insert_precord(gid, precord);
                    self.refresh_dynamic_hooks_for_pid_if_due(pid_u32);

                    // Register in learning engine
                    #[cfg(feature = "realtime_learning")]
                    {
                        self.learning_engine.track_process(gid, appname.clone());
                        self.api_trackers
                            .insert(gid, ApiTracker::new(gid, appname.clone()));
                    }

                    discovered_new += 1;
                }

                if discovered_new > 0 {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Discovered {} new processes",
                        discovered_new
                    ));
                }

                // --- THIRD: Sync behavior engine state to process_records ---
                #[cfg(all(target_os = "windows", feature = "firewall"))]
                self.sync_firewall_process_contexts();
                for (gid, state) in self.behavior_engine.process_states.iter() {
                    if self.process_records.get_precord_by_gid(*gid).is_none() {
                        let mut precord = ProcessRecord::new(
                            *gid,
                            state.app_name.clone(),
                            state.exe_path.clone(),
                        );
                        precord.pids.insert(state.pid);
                        self.process_records.insert_precord(*gid, precord);
                        Logging::debug(&format!(
                            "[PROCESS SYNC] Registered GID: {} from behavior_engine",
                            gid
                        ));
                    }
                }

                // Log Current Status
                let total_tracked = self.behavior_engine.process_states.len();
                if total_tracked > 0 {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Evaluating {} tracked processes",
                        total_tracked
                    ));
                } else {
                    Logging::warning("[BEHAVIOR SCAN] No processes are being tracked!");
                }

                // --- FOURTH: Run the scan on all tracked processes ---
                let detections = self
                    .behavior_engine
                    .scan_all_processes(config, &*threat_handler);

                if !detections.is_empty() {
                    Logging::info(&format!(
                        "[BEHAVIOR SCAN] Found {} detections",
                        detections.len()
                    ));
                }

                // --- FIFTH: Apply detections to process records ---
                let mut terminated_gids = HashSet::new();
                for det in detections {
                    if terminated_gids.contains(&det.gid) {
                        continue;
                    }

                    let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                    let threat_info =
                        Self::build_behavior_threat_info(&det, "periodic behavior scan");
                    let matching_record = self
                        .process_records
                        .process_records
                        .iter_mut()
                        .find(|(gid, _)| **gid == det.gid);

                    if let Some((_, record)) = matching_record {
                        Self::apply_behavior_detection_state(record, &det);
                        #[cfg(feature = "realtime_learning")]
                        Self::mark_realtime_process_malicious(
                            &mut self.learning_engine,
                            &self.api_trackers,
                            det.gid,
                            record,
                        );
                        let rule_name = det
                            .triggered_rule_name
                            .as_deref()
                            .unwrap_or("Behavioral Detection");
                        Logging::warning(&format!(
                            "[DETECTION] Process {} (GID: {}) marked malicious by rule '{}'",
                            record.appname, det.gid, rule_name
                        ));
                        ActionsOnKill::with_handler(threat_handler.clone_box())
                            .run_actions_with_info(config, record, &dummy_pred_mtrx, &threat_info);

                        if det.termination_requested
                            && restart_cleanup_reason(record, &threat_info).is_none()
                        {
                            terminated_gids.insert(det.gid);
                        }
                    } else if let Some(state) = self.behavior_engine.process_states.get(&det.gid) {
                        // Handle detection for process not yet in records
                        let mut precord = ProcessRecord::new(
                            det.gid,
                            state.app_name.clone(),
                            state.exe_path.clone(),
                        );
                        Self::apply_behavior_detection_state(&mut precord, &det);
                        #[cfg(feature = "realtime_learning")]
                        Self::mark_realtime_process_malicious(
                            &mut self.learning_engine,
                            &self.api_trackers,
                            det.gid,
                            &precord,
                        );
                        ActionsOnKill::with_handler(threat_handler.clone_box())
                            .run_actions_with_info(
                                config,
                                &mut precord,
                                &dummy_pred_mtrx,
                                &threat_info,
                            );

                        if det.termination_requested
                            && restart_cleanup_reason(&precord, &threat_info).is_none()
                        {
                            terminated_gids.insert(det.gid);
                        } else {
                            self.process_records.insert_precord(det.gid, precord);
                        }
                    }
                }

                for gid in terminated_gids.clone() {
                    self.cleanup_process(gid, "Killed (behavior detection)");
                }

                // --- SIXTH: Check for Sanctum Detections (Worker-level Handling) ---
                #[cfg(all(target_os = "windows", feature = "sanctum"))]
                {
                    let sanctum_stats = self
                        .behavior_engine
                        .firewall_sanctum_stats
                        .read()
                        .unwrap()
                        .clone();
                    let mut sanctum_deep_scan_requests: Vec<(PathBuf, u32, String)> = Vec::new();
                    for (pid, stats) in sanctum_stats {
                        if stats.is_detection {
                            if let Some(gid) = self.find_gid_by_pid(pid) {
                                if !terminated_gids.contains(&gid) {
                                    let matching_record =
                                        self.process_records.process_records.get_mut(&gid);
                                    if let Some(record) = matching_record {
                                        if !record.is_malicious {
                                            Logging::alert(&format!(
                                                "[SanctumDetection] 🚨 ENFORCING: Marking PID {} Malicious based on Sanctum telemetry",
                                                pid
                                            ));
                                            record.is_malicious = true;
                                            record.termination_requested = true;
                                            record.notify_user_requested = true;
                                            record.triggered_rule_name =
                                                Some("SanctumEDR_Detection".to_string());

                                            #[cfg(feature = "realtime_learning")]
                                            Self::mark_realtime_process_malicious(
                                                &mut self.learning_engine,
                                                &self.api_trackers,
                                                gid,
                                                record,
                                            );

                                            let dummy_pred_mtrx = VecvecCappedF32::new(0, 0);
                                            sanctum_deep_scan_requests.push((
                                                record.exepath.clone(),
                                                pid,
                                                format!(
                                                    "Sanctum detection: {}",
                                                    stats.last_event.clone().unwrap_or_default()
                                                ),
                                            ));
                                            let threat_info = ThreatInfo {
                                                threat_type_label: "Sanctum EDR Detection",
                                                virus_name: "Sanctum.Malware.Gen",
                                                prediction: 1.0,
                                                match_details: Some(format!(
                                                    "Sanctum Detection: {}",
                                                    stats.last_event.clone().unwrap_or_default()
                                                )),
                                                deny_access: false,
                                                terminate: true,
                                                quarantine: false,
                                                kill_and_remove: false,
                                                suspend: false,
                                                notify_user: true,
                                                revert: false,
                                            };
                                            ActionsOnKill::with_handler(threat_handler.clone_box())
                                                .run_actions_with_info(
                                                    config,
                                                    record,
                                                    &dummy_pred_mtrx,
                                                    &threat_info,
                                                );

                                            if restart_cleanup_reason(record, &threat_info)
                                                .is_none()
                                            {
                                                terminated_gids.insert(gid);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                    if let Some(av_integration) = self.av_integration.as_mut() {
                        for (path, pid, context) in sanctum_deep_scan_requests {
                            av_integration.queue_deep_scan_request(&path, Some(pid), Some(context));
                        }
                    }
                }

                for gid in terminated_gids {
                    if self.process_records.process_records.contains(&gid) {
                        self.cleanup_process(gid, "Killed (Sanctum/Behavior Detection)");
                    }
                }

                // --- SEVENTH: Real-time learning periodic checks ---
                #[cfg(feature = "realtime_learning")]
                {
                    self.learning_engine
                        .check_benign_processes(&self.api_trackers, |gid| {
                            self.process_records.process_records.peek(&gid)
                        });
                }
            }
        }

        pub fn new_replay(
            config: &'a Config,
            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            app_settings: AppSettings,
        ) -> Worker<'a> {
            Worker {
                config,
                process_records: ProcessRecords::new(),
                process_record_handler: Some(Box::new(ProcessRecordHandlerReplay::new(config))),
                exepath_handler: Box::<ExePathReplay>::default(),
                iomsg_postprocessors: vec![],
                #[cfg(all(target_os = "windows", feature = "hydradragon"))]
                av_integration: None,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                behavior_engine: Self::build_behavior_engine(config),
                #[cfg(feature = "realtime_learning")]
                learning_engine: {
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    let trust_path = Some(app_settings.win_verify_trust_path.to_str().unwrap());
                    #[cfg(not(all(target_os = "windows", feature = "behavior_engine")))]
                    let trust_path = None;

                    crate::realtime_learning::RealtimeLearningEngine::new(
                        Self::realtime_learning_output_dir(config),
                        trust_path,
                    )
                },
                #[cfg(feature = "realtime_learning")]
                api_trackers: HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                app_settings,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hooks_registered: false,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_event_map: Self::default_dynamic_hook_event_map(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_registered_apis: Self::default_registered_dynamic_apis(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                next_dynamic_hook_event_id: Self::DYNAMIC_HOOK_EVENT_ID_START,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_registration_blocked: false,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_last_refresh: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_target_generation: 0,
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_applied_generation: std::collections::HashMap::new(),
                #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                dynamic_hook_apply_failures: std::collections::HashMap::new(),
                threat_handler: None,
                #[cfg(target_os = "windows")]
                driver: None,
                last_report_time: None,
            }
        }

        /// Process kernel I/O event - this is the main event handler
        pub fn process_io(&mut self, iomsg: &mut IOMessage, config: &crate::config::Config) {
            let irp_op = iomsg.irp_op;
            let is_process_create = irp_op == IrpMajorOp::IrpProcessCreate as u8;
            let is_process_terminate = irp_op == IrpMajorOp::IrpProcessTerminate as u8;
            let _ = is_process_create;
            let _ = is_process_terminate;

            self.normalize_tracking_gid(iomsg);

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                let now = std::time::Instant::now();
                let report_interval = std::time::Duration::from_secs(3600); // 1 hour
                use std::sync::atomic::Ordering; // Import Ordering
                let force_report = self
                    .behavior_engine
                    .generate_report_flag
                    .swap(false, Ordering::SeqCst);
                if force_report
                    || self
                        .last_report_time
                        .map_or(true, |t| now.duration_since(t) > report_interval)
                {
                    if force_report {
                        Logging::info("[REPORT] Triggering on-demand report requested via pipe");
                    }
                    self.generate_system_report();
                }
            }

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            {
                let irp_kind_for_name_resolution = IrpMajorOp::from_byte(iomsg.irp_op);
                if matches!(
                    irp_kind_for_name_resolution,
                    IrpMajorOp::IrpHypervisorEvent | IrpMajorOp::IrpUserModeHookEvent
                ) {
                    iomsg.normalize_hypervisor_event();

                    let raw_event_type = effective_hypervisor_raw_event_type(iomsg);
                    let needs_name_resolution = iomsg.needs_hypervisor_name_resolution();
                    if needs_name_resolution
                        && let Some(mapped_api) = self.dynamic_hook_event_map.get(&raw_event_type)
                    {
                        iomsg.kernel_event_info.object_name = mapped_api.clone();
                    }
                }
            }

            let irp_op = IrpMajorOp::from_byte(iomsg.irp_op);
            let is_process_create = irp_op == IrpMajorOp::IrpProcessCreate;
            let is_process_terminate = irp_op == IrpMajorOp::IrpProcessTerminate;
            let _ = is_process_create;
            let _ = is_process_terminate;

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            if Self::is_unattributed_rootkit_event(iomsg, &irp_op) {
                Logging::warning(&format!(
                    "[ROOTKIT] Routing unattributed kernel finding through global handler only: opcode={:?} desc={}",
                    irp_op,
                    iomsg.kernel_event_info.object_name.trim_matches('\0')
                ));
                self.behavior_engine.handle_rootkit_event(iomsg);
                return;
            }

            // Register or update process record based on kernel event
            self.register_precord(iomsg);
            let tracking_key = iomsg.gid;

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            if !is_process_terminate {
                self.refresh_dynamic_hooks_for_pid_if_due(iomsg.pid);
            }

            // Backfill command line for events that don't carry it (e.g., kernel API hook events).
            if iomsg.runtime_features.command_line.trim().is_empty()
                && let Some(precord) = self.process_records.get_precord_by_gid(tracking_key)
                && !precord.command_line.trim().is_empty()
            {
                iomsg.runtime_features.command_line = precord.command_line.clone();
            }

            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
            if is_process_create {
                self.refresh_dynamic_hooks_for_pid_if_due(iomsg.pid);
            }

            #[cfg(all(
                target_os = "windows",
                feature = "behavior_engine",
                feature = "firewall"
            ))]
            if is_process_create && self.threat_handler.is_some() {
                self.sync_firewall_process_contexts();
            }

            if let Some(precord) = self.process_records.get_precord_mut_by_gid(tracking_key) {
                // For new processes (after startup flood), run static scan
                // immediately so pre-loaded malware state is caught on creation.
                // Skipped during startup_complete=false to avoid the O(n²)
                // per-IrpProcessCreate scan backlog; the periodic 750ms scan covers it.
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

                // Update learning engine before detection-time collection so the
                // triggering event is part of the malicious sample.
                #[cfg(feature = "realtime_learning")]
                {
                    Self::record_realtime_event(
                        &mut self.learning_engine,
                        &mut self.api_trackers,
                        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                        &self.behavior_engine,
                        tracking_key,
                        iomsg,
                        precord,
                    );
                }

                {
                    // Heal stale appname/exepath before ANY detection runs.
                    // register_precord may have left "PROC_<pid>" / "UNKNOWN" if the
                    // IrpProcessCreate event hasn't arrived yet.  Try the exepath handler
                    // one more time so ransomware detection, reports, and all other paths
                    // get correct values from the very first event.
                    let precord_name_stale = precord.appname.is_empty()
                        || precord.appname.starts_with("PROC_")
                        || precord.appname == "UNKNOWN";
                    let precord_path_stale = precord.exepath.to_string_lossy() == "UNKNOWN"
                        || precord.exepath.as_os_str().is_empty();

                    if (precord_name_stale || precord_path_stale)
                        && let Some(resolved_path) = self.exepath_handler.exepath(iomsg)
                        && resolved_path.to_string_lossy() != "UNKNOWN"
                        && !resolved_path.as_os_str().is_empty()
                    {
                        let resolved_name =
                            Self::appname_from_exepath_static(&resolved_path).unwrap_or_default();
                        if precord_path_stale {
                            precord.exepath = resolved_path.clone();
                        }
                        if precord_name_stale && !resolved_name.is_empty() {
                            precord.appname = resolved_name.clone();
                        }
                        // Propagate to behavior engine state so rule matching
                        // and allowlists are also correct immediately.
                        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                        if let Some(state) =
                            self.behavior_engine.process_states.get_mut(&tracking_key)
                            && (state.app_name.is_empty()
                                || state.app_name.starts_with("PROC_")
                                || state.app_name == "UNKNOWN")
                        {
                            if !resolved_name.is_empty() {
                                state.app_name = resolved_name;
                            }
                            state.exe_path = resolved_path;
                        }
                    }

                    // Process behavioral event
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    if let Some(ref th) = self.threat_handler {
                        let was_malicious = precord.is_malicious;
                        self.behavior_engine
                            .process_event(precord, iomsg, config, &**th);

                        #[cfg(feature = "realtime_learning")]
                        if !was_malicious && precord.is_malicious {
                            Self::mark_realtime_process_malicious(
                                &mut self.learning_engine,
                                &self.api_trackers,
                                tracking_key,
                                precord,
                            );
                        }
                    }

                    // Run process record handler (e.g., prediction)
                    if let Some(process_record_handler) = &mut self.process_record_handler {
                        process_record_handler.handle_io(precord);
                    }

                    // Handle process termination
                    if is_process_terminate {
                        precord.process_state = ProcessState::Terminated;
                        Logging::info(&format!(
                            "[KERNEL] Process Terminated: {} (GID: {}, PID: {})",
                            precord.appname, precord.gid, iomsg.pid
                        ));
                    }

                    // Run postprocessors
                    for postprocessor in &mut self.iomsg_postprocessors {
                        postprocessor.postprocess(iomsg, precord);
                    }
                }
            }

            // FIX: Cleanup on termination - works regardless of feature flags
            if is_process_terminate {
                self.cleanup_process(tracking_key, "Process terminated");
            }
        }

        pub fn process_suspended_records(
            &mut self,
            config: &Config,
            threat_handler: Box<dyn ThreatHandler>,
        ) {
            self.process_records
                .process_suspended_procs(config, threat_handler);

            // FIX: Cleanup terminated processes regardless of feature flags
            let mut terminated_gids = Vec::new();
            for (gid, proc) in self.process_records.process_records.iter() {
                if proc.process_state == ProcessState::Terminated {
                    terminated_gids.push(*gid);
                }
            }

            for gid in terminated_gids {
                self.cleanup_process(gid, "Suspended terminated");
            }
        }

        /// Register or update process record from kernel event
        /// This is the ONLY place where processes should be added to tracking
        fn register_precord(&mut self, iomsg: &mut IOMessage) {
            let gid = iomsg.gid;
            let pid = iomsg.pid;

            if Self::is_internal_service_pid(pid) {
                return;
            }

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
                        && !iomsg.filepathstr.is_empty()
                    {
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
                        Logging::warning(&format!(
                            "{} [UNRESOLVED] Process: {} (GID: {}, PID: {})",
                            log_type, appname, gid, pid
                        ));
                    } else {
                        Logging::info(&format!(
                            "{} New Process: {} (GID: {}, PID: {}, Path: {})",
                            log_type,
                            appname,
                            gid,
                            pid,
                            exepath.display()
                        ));
                    }

                    // Create process record
                    let precord = ProcessRecord::from(iomsg, appname.clone(), exepath.clone());

                    // Register in behavior engine
                    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                    {
                        self.behavior_engine.register_process(
                            gid,
                            pid,
                            exepath.clone(),
                            appname.clone(),
                        );
                    }

                    // Register in learning engine
                    #[cfg(feature = "realtime_learning")]
                    {
                        self.learning_engine.track_process(gid, appname.clone());
                        Self::record_realtime_event(
                            &mut self.learning_engine,
                            &mut self.api_trackers,
                            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                            &self.behavior_engine,
                            gid,
                            iomsg,
                            &precord,
                        );
                    }

                    // Store process record (moves precord)
                    self.process_records.insert_precord(gid, precord);
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
                                old_name,
                                name,
                                gid,
                                pid,
                                path.display()
                            ));

                            precord.exepath = path.clone();
                            precord.appname = name.clone();

                            // Update behavior engine
                            #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
                            {
                                if let Some(state) =
                                    self.behavior_engine.process_states.get_mut(&gid)
                                {
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

        fn appname_from_exepath_static(exepath: &Path) -> Option<String> {
            exepath.file_name()?.to_str().map(|s| s.to_string())
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn is_api_already_registered(&self, api_spec: &str) -> bool {
            self.dynamic_registered_apis
                .contains(&api_spec.to_ascii_lowercase())
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn resolve_or_allocate_dynamic_event_id(&mut self, api_spec: &str) -> Option<u32> {
            if let Some((event_id, _)) = self
                .dynamic_hook_event_map
                .iter()
                .find(|(_, existing_api)| existing_api.eq_ignore_ascii_case(api_spec))
            {
                return Some(*event_id);
            }

            let mut candidate = self
                .next_dynamic_hook_event_id
                .max(Self::DYNAMIC_HOOK_EVENT_ID_START);

            while self.dynamic_hook_event_map.contains_key(&candidate) {
                if candidate == u32::MAX {
                    return None;
                }
                candidate += 1;
            }

            self.next_dynamic_hook_event_id = candidate.saturating_add(1);
            Some(candidate)
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn normalize_hook_module_name(raw: &str) -> String {
            let module = raw.trim();
            if module.is_empty() || module == "*" {
                return module.to_string();
            }

            if module.eq_ignore_ascii_case("exe") {
                return "exe".to_string();
            }

            // Allow full paths (user explicitly specified one).
            if module.contains('\\') || module.contains('/') {
                return module.to_string();
            }

            // If the user already specified an extension (e.g. ntdll.dll), keep it.
            if module.rsplit_once('.').is_some() {
                return module.to_string();
            }

            // Driver compares against BaseDllName (e.g. "advapi32.dll"), so add ".dll" by default.
            format!("{module}.dll")
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn looks_like_hook_offset(raw: &str) -> bool {
            let mut value = raw.trim();
            if value.is_empty() {
                return false;
            }

            if let Some(stripped) = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                value = stripped;
            }
            if let Some(stripped) = value.strip_suffix('h').or_else(|| value.strip_suffix('H')) {
                value = stripped;
            }

            !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn split_module_rva_target(api_spec: &str) -> Option<(&str, &str)> {
            let trimmed = api_spec.trim();
            let (module_raw, offset_raw) = trimmed.rsplit_once('+')?;
            let module = module_raw.trim();
            let offset = offset_raw.trim();

            if module.is_empty() || offset.is_empty() || module.contains('!') {
                return None;
            }

            if !Self::looks_like_hook_offset(offset) {
                return None;
            }

            Some((module, offset))
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn push_unique_hook_target(
            seen_lower: &mut HashSet<String>,
            targets: &mut Vec<String>,
            api_spec: impl Into<String>,
        ) {
            let api_spec = api_spec.into();
            let trimmed = api_spec.trim();
            if trimmed.is_empty() {
                return;
            }

            let key = trimmed.to_ascii_lowercase();
            if seen_lower.insert(key) {
                targets.push(trimmed.to_string());
            }
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn known_hook_function_variants(function_pattern: &str) -> Vec<&'static str> {
            let lowered = function_pattern.trim().to_ascii_lowercase();
            let mut variants = Vec::new();
            let mut push = |name: &'static str| {
                if !variants.contains(&name) {
                    variants.push(name);
                }
            };

            if lowered.contains("setwineventhook") {
                push("SetWinEventHook");
                push("SetWinEventHookA");
                push("SetWinEventHookW");
                push("NtUserSetWinEventHook");
            }
            if lowered.contains("setwindowshookex") {
                push("SetWindowsHookExA");
                push("SetWindowsHookExW");
                push("NtUserSetWindowsHookEx");
            }
            if lowered.contains("setwindowshook") {
                push("SetWindowsHookA");
                push("SetWindowsHookW");
            }
            if lowered.contains("dnsqueryex") {
                push("DnsQueryEx");
            }
            if lowered.contains("dnsquery_a") {
                push("DnsQuery_A");
            }
            if lowered.contains("dnsquery_w") {
                push("DnsQuery_W");
            }
            if lowered.contains("dnsquery") {
                push("DnsQuery_A");
                push("DnsQuery_W");
                push("DnsQuery_UTF8");
                push("DnsQueryEx");
            }
            if lowered.contains("querydnsconfig") {
                push("QueryDnsConfig");
            }
            if lowered.contains("getaddrinfo") {
                push("getaddrinfo");
                push("GetAddrInfoW");
                push("GetAddrInfoExW");
            }
            if lowered.contains("createserviceex") {
                push("CreateServiceExA");
                push("CreateServiceExW");
            }
            if lowered.contains("createservice") {
                push("CreateServiceA");
                push("CreateServiceW");
                push("CreateServiceExA");
                push("CreateServiceExW");
            }
            if lowered.contains("changeserviceconfig2") {
                push("ChangeServiceConfig2A");
                push("ChangeServiceConfig2W");
            }
            if lowered.contains("changeserviceconfig") {
                push("ChangeServiceConfigA");
                push("ChangeServiceConfigW");
                push("ChangeServiceConfig2A");
                push("ChangeServiceConfig2W");
            }
            if lowered.contains("openscmanager") {
                push("OpenSCManagerA");
                push("OpenSCManagerW");
            }
            if lowered.contains("openservice") {
                push("OpenServiceA");
                push("OpenServiceW");
            }
            if lowered.contains("startservice") {
                push("StartServiceA");
                push("StartServiceW");
            }
            if lowered.contains("regcreatekeyex") {
                push("RegCreateKeyExA");
                push("RegCreateKeyExW");
            }
            if lowered.contains("regcreatekey") {
                push("RegCreateKeyA");
                push("RegCreateKeyW");
                push("RegCreateKeyExA");
                push("RegCreateKeyExW");
            }
            if lowered.contains("regsetkeyvalue") {
                push("RegSetKeyValueA");
                push("RegSetKeyValueW");
            }
            if lowered.contains("regsetvalueex") {
                push("RegSetValueExA");
                push("RegSetValueExW");
            }
            if lowered.contains("regsetvalue") {
                push("RegSetValueA");
                push("RegSetValueW");
                push("RegSetValueExA");
                push("RegSetValueExW");
                push("RegSetKeyValueA");
                push("RegSetKeyValueW");
            }
            if lowered.contains("ntloaddriver") {
                push("NtLoadDriver");
            }
            if lowered.contains("zwloaddriver") {
                push("ZwLoadDriver");
            }
            if lowered.contains("ntcreatekey") {
                push("NtCreateKey");
            }
            if lowered.contains("zwcreatekey") {
                push("ZwCreateKey");
            }
            if lowered.contains("ntsetvaluekey") {
                push("NtSetValueKey");
            }
            if lowered.contains("zwsetvaluekey") {
                push("ZwSetValueKey");
            }
            if lowered.contains("ntcreatefile") {
                push("NtCreateFile");
            }
            if lowered.contains("zwcreatefile") {
                push("ZwCreateFile");
            }
            if lowered.contains("ntwritefile") {
                push("NtWriteFile");
            }
            if lowered.contains("zwwritefile") {
                push("ZwWriteFile");
            }
            if lowered.contains("ntsetinformationfile") {
                push("NtSetInformationFile");
            }
            if lowered.contains("zwsetinformationfile") {
                push("ZwSetInformationFile");
            }
            if lowered.contains("ntfscontrolfile") {
                push("NtFsControlFile");
            }
            if lowered.contains("zwfscontrolfile") {
                push("ZwFsControlFile");
            }
            if lowered.contains("createfile") {
                push("CreateFileA");
                push("CreateFileW");
            }
            if lowered.contains("readfile") {
                push("ReadFile");
            }
            if lowered.contains("writefile") {
                push("WriteFile");
            }
            if lowered.contains("copyfileex") {
                push("CopyFileExA");
                push("CopyFileExW");
            }
            if lowered.contains("copyfile") {
                push("CopyFileA");
                push("CopyFileW");
                push("CopyFileExA");
                push("CopyFileExW");
            }
            if lowered.contains("movefileex") {
                push("MoveFileExA");
                push("MoveFileExW");
            }
            if lowered.contains("movefile") {
                push("MoveFileA");
                push("MoveFileW");
                push("MoveFileExA");
                push("MoveFileExW");
            }
            if lowered.contains("replacefile") {
                push("ReplaceFileA");
                push("ReplaceFileW");
            }
            if lowered.contains("deviceiocontrol") {
                push("DeviceIoControl");
            }
            if lowered.contains("cocreateinstance") {
                push("CoCreateInstance");
                push("CoCreateInstanceEx");
            }
            if lowered.contains("cogetobject") {
                push("CoGetObject");
            }
            if lowered.contains("cogetclassobject") {
                push("CoGetClassObject");
            }
            if lowered.contains("coinitializesecurity") {
                push("CoInitializeSecurity");
            }
            if lowered.contains("cosetproxyblanket") {
                push("CoSetProxyBlanket");
            }
            if lowered.contains("impersonateloggedonuser") {
                push("ImpersonateLoggedOnUser");
            }
            if lowered.contains("setthreadtoken") {
                push("SetThreadToken");
            }
            if lowered.contains("duplicatetokenex") {
                push("DuplicateTokenEx");
            }
            if lowered.contains("openthreadtoken") {
                push("OpenThreadToken");
            }
            if lowered.contains("openprocesstoken") {
                push("OpenProcessToken");
            }
            if lowered.contains("adjusttokenprivileges") {
                push("AdjustTokenPrivileges");
            }
            if lowered.contains("impersonatenamedpipeclient") {
                push("ImpersonateNamedPipeClient");
            }
            if lowered.contains("createprocesswithtokenw") {
                push("CreateProcessWithTokenW");
            }
            if lowered.contains("createprocessasuserw") {
                push("CreateProcessAsUserW");
            }
            if lowered.contains("ntimpersonatethread") {
                push("NtImpersonateThread");
            }
            if lowered.contains("ntsetinformationthread") {
                push("NtSetInformationThread");
            }

            variants
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn expand_dynamic_hook_api_target(api_spec: &str) -> Vec<String> {
            let trimmed = api_spec.trim();
            if trimmed.is_empty() {
                return Vec::new();
            }

            let mut expanded = Vec::new();
            let mut seen_lower = HashSet::new();

            if let Some((module_raw, offset_raw)) = Self::split_module_rva_target(trimmed) {
                let module = Self::normalize_hook_module_name(module_raw);
                Self::push_unique_hook_target(
                    &mut seen_lower,
                    &mut expanded,
                    format!("{module}!rva:{}", offset_raw.trim()),
                );
                return expanded;
            }

            if let Some((module_raw, function_raw)) = trimmed.split_once('!') {
                let module = Self::normalize_hook_module_name(module_raw);
                let function_variants = Self::known_hook_function_variants(function_raw);
                if function_variants.is_empty() {
                    Self::push_unique_hook_target(
                        &mut seen_lower,
                        &mut expanded,
                        format!("{module}!{}", function_raw.trim()),
                    );
                } else {
                    for function in function_variants {
                        Self::push_unique_hook_target(
                            &mut seen_lower,
                            &mut expanded,
                            format!("{module}!{function}"),
                        );
                    }
                }
                return expanded;
            }

            let lowered = trimmed.to_ascii_lowercase();
            let normalized_name = trimmed.trim_matches(|c| c == '*' || c == '?').trim();
            let mut add_many = |module: &str, functions: &[&str]| {
                let normalized_module = Self::normalize_hook_module_name(module);
                for function in functions {
                    Self::push_unique_hook_target(
                        &mut seen_lower,
                        &mut expanded,
                        format!("{normalized_module}!{function}"),
                    );
                }
            };

            match lowered.as_str() {
                value if value.contains("setwineventhook") => {
                    add_many(
                        "user32.dll",
                        &["SetWinEventHook", "SetWinEventHookA", "SetWinEventHookW"],
                    );
                    add_many("win32u.dll", &["NtUserSetWinEventHook"]);
                }
                value if value.contains("setwindowshookex") => {
                    add_many("user32.dll", &["SetWindowsHookExA", "SetWindowsHookExW"]);
                    add_many("win32u.dll", &["NtUserSetWindowsHookEx"]);
                }
                value if value.contains("setwindowshook") => {
                    add_many(
                        "user32.dll",
                        &[
                            "SetWindowsHookA",
                            "SetWindowsHookW",
                            "SetWindowsHookExA",
                            "SetWindowsHookExW",
                        ],
                    );
                }
                value if value.contains("dnsquery") => {
                    add_many(
                        "dnsapi.dll",
                        &["DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "DnsQueryEx"],
                    );
                }
                value if value.contains("querydnsconfig") => {
                    add_many("dnsapi.dll", &["QueryDnsConfig"]);
                }
                value if value.contains("getaddrinfo") => {
                    add_many(
                        "ws2_32.dll",
                        &["getaddrinfo", "GetAddrInfoW", "GetAddrInfoExW"],
                    );
                }
                value
                    if value.contains("createservice")
                        || value.contains("changeserviceconfig")
                        || value.contains("openscmanager")
                        || value.contains("openservice")
                        || value.contains("startservice")
                        || value.contains("regcreatekey")
                        || value.contains("regsetvalue")
                        || value.contains("regsetkeyvalue")
                        || value.contains("impersonateloggedonuser")
                        || value.contains("setthreadtoken")
                        || value.contains("duplicatetokenex")
                        || value.contains("openthreadtoken")
                        || value.contains("openprocesstoken")
                        || value.contains("adjusttokenprivileges")
                        || value.contains("impersonatenamedpipeclient")
                        || value.contains("createprocesswithtokenw")
                        || value.contains("createprocessasuserw") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("advapi32.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("advapi32.dll", &variants);
                    }
                }
                value if value.contains("nt") || value.contains("zw") => {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("ntdll.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("ntdll.dll", &variants);
                    }
                }
                value
                    if value.contains("cocreateinstance")
                        || value.contains("cogetobject")
                        || value.contains("cogetclassobject")
                        || value.contains("coinitializesecurity")
                        || value.contains("cosetproxyblanket") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("ole32.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("ole32.dll", &variants);
                    }
                }
                value
                    if value.contains("createfile")
                        || value.contains("readfile")
                        || value.contains("writefile")
                        || value.contains("copyfile")
                        || value.contains("movefile")
                        || value.contains("replacefile")
                        || value.contains("deviceiocontrol") =>
                {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if variants.is_empty() {
                        if !normalized_name.is_empty() {
                            add_many("kernel32.dll", &[normalized_name]);
                            add_many("kernelbase.dll", &[normalized_name]);
                        }
                    } else {
                        add_many("kernel32.dll", &variants);
                        add_many("kernelbase.dll", &variants);
                    }
                }
                _ => {
                    let variants = Self::known_hook_function_variants(trimmed);
                    if !variants.is_empty() {
                        for function in variants {
                            let function_lower = function.to_ascii_lowercase();
                            if function_lower.starts_with("ntuser") {
                                add_many("win32u.dll", &[function]);
                            } else if function_lower.starts_with("nt")
                                || function_lower.starts_with("zw")
                            {
                                add_many("ntdll.dll", &[function]);
                            } else if function_lower.starts_with("co") {
                                add_many("ole32.dll", &[function]);
                            } else if function_lower.contains("dns") {
                                add_many("dnsapi.dll", &[function]);
                            } else if function_lower.contains("addrinfo") {
                                add_many("ws2_32.dll", &[function]);
                            } else if function_lower.contains("service")
                                || function_lower.starts_with("reg")
                                || function_lower.contains("token")
                                || function_lower.contains("impersonate")
                            {
                                add_many("advapi32.dll", &[function]);
                            } else if function_lower.contains("file")
                                || function_lower.contains("deviceiocontrol")
                            {
                                add_many("kernel32.dll", &[function]);
                                add_many("kernelbase.dll", &[function]);
                            } else if function_lower.contains("hook") {
                                add_many("user32.dll", &[function]);
                            }
                        }
                    }
                }
            }

            if expanded.is_empty() {
                Self::push_unique_hook_target(&mut seen_lower, &mut expanded, trimmed.to_string());
            }

            expanded
        }

        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn collect_dynamic_hook_api_targets(&mut self, _pid: u32) -> Vec<String> {
            let mut seen_lower = HashSet::new();
            let mut merged = Vec::new();

            let mut rule_apis: Vec<String> = self
                .behavior_engine
                .get_all_monitored_apis()
                .into_iter()
                .collect();
            rule_apis.sort_unstable();
            for api in rule_apis {
                let trimmed = api.trim();
                if trimmed.is_empty() {
                    continue;
                }
                for expanded_api in Self::expand_dynamic_hook_api_target(trimmed) {
                    Self::push_unique_hook_target(&mut seen_lower, &mut merged, expanded_api);
                }
            }

            merged
        }

        /// Register high-interest API hooks for a specific PID
        /// Keeps dynamic hooks rule-driven. Import-wide expansion is intentionally
        /// disabled because broad hook sets are too unstable.
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        fn register_dynamic_hooks_for_process(&mut self, pid: u32) {
            if Self::should_skip_dynamic_hooks_for_pid(pid) {
                return;
            }

            if self.dynamic_hook_registration_blocked {
                return;
            }

            let Some(driver) = self.driver.clone() else {
                Logging::warning(&format!(
                    "[DYNAMIC HOOK] Driver not available, cannot hook PID {}",
                    pid
                ));
                return;
            };

            let monitored_apis = self.collect_dynamic_hook_api_targets(pid);
            if monitored_apis.is_empty() {
                return;
            }

            let mut registered_count = 0;
            let mut already_registered_count = 0;
            let mut failed_count = 0;
            let mut wildcard_count = 0;

            for api_spec in monitored_apis {
                if self.is_api_already_registered(&api_spec) {
                    already_registered_count += 1;
                    continue;
                }

                let Some(event_id) = self.resolve_or_allocate_dynamic_event_id(&api_spec) else {
                    self.dynamic_hook_registration_blocked = true;
                    Logging::warning(
                        "[DYNAMIC HOOK] Event-id pool exhausted; stopping new registrations",
                    );
                    break;
                };

                let (module, function) = if let Some(idx) = api_spec.find('!') {
                    (
                        Self::normalize_hook_module_name(&api_spec[..idx]),
                        api_spec[idx + 1..].to_string(),
                    )
                } else {
                    wildcard_count += 1;
                    ("*".to_string(), api_spec.clone())
                };

                // SharedDefs.HOOK_CONFIG_DATA currently supports ModuleName[64] and FunctionName[256].
                if module != "*" && module.len() >= 64 {
                    failed_count += 1;
                    Logging::warning(&format!(
                        "[DYNAMIC HOOK] PID {} registration failed: module name too long ({} chars): {}",
                        pid,
                        module.len(),
                        module
                    ));
                    continue;
                }
                if function.len() >= 256 {
                    failed_count += 1;
                    Logging::warning(&format!(
                        "[DYNAMIC HOOK] PID {} registration failed: function name too long ({} chars): {}!{}",
                        pid,
                        function.len(),
                        module,
                        function
                    ));
                    continue;
                }

                match driver.add_hook_target(&module, &function, event_id) {
                    Ok(_) => {
                        self.dynamic_registered_apis
                            .insert(api_spec.to_ascii_lowercase());
                        self.dynamic_hook_event_map.insert(event_id, api_spec);
                        registered_count += 1;
                    }
                    Err(e) => {
                        let hr = e.code().0 as u32;
                        if hr == 0x800705AA || hr == 0x8007000E {
                            self.dynamic_hook_registration_blocked = true;
                            Logging::error(&format!(
                                "[DYNAMIC HOOK] Resource exhaustion while registering PID {} (hr=0x{:08X}); pausing new hooks",
                                pid, hr
                            ));
                            break;
                        }
                        failed_count += 1;
                        Logging::error(&format!(
                            "[DYNAMIC HOOK] Failed registration PID {} event {} {}!{}: {}",
                            pid, event_id, module, function, e
                        ));
                    }
                }
            }

            if registered_count > 0 {
                self.dynamic_hook_target_generation =
                    self.dynamic_hook_target_generation.saturating_add(1);
            }

            let target_generation = self.dynamic_hook_target_generation;
            let applied_generation = self
                .dynamic_hook_applied_generation
                .get(&pid)
                .copied()
                .unwrap_or(0);
            let has_any_targets = registered_count > 0 || already_registered_count > 0;
            let needs_apply = has_any_targets && applied_generation < target_generation;

            if needs_apply {
                if let Err(e) = driver.hook_process(pid) {
                    let hr = e.code().0 as u32;
                    let low_word = hr & 0xFFFF;
                    let is_noaccess_like =
                        hr == 0x800703E6 || hr == 0xC0000005 || low_word == 0x03E6;
                    if hr == 0x80070677 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: process mitigation blocks dynamic code (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x80070005 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: access denied (likely protected/critical process) (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if is_noaccess_like {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: NOACCESS while patching hooks (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x80070016 {
                        self.dynamic_hook_apply_failures.remove(&pid);
                        Logging::warning(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: driver command not recognized for this target (hr=0x{:08X})",
                            pid, hr
                        ));
                    } else if hr == 0x8007001F {
                        let failures = self.dynamic_hook_apply_failures.entry(pid).or_insert(0);
                        *failures = failures.saturating_add(1);
                        Logging::error(&format!(
                            "[DYNAMIC HOOK] PID {} apply failed: generic driver failure (hr=0x{:08X}); inspect kernel 'UserModeHook' / 'MESSAGE_HOOK_PROCESS' debug output for the exact NTSTATUS",
                            pid, hr
                        ));
                    } else {
                        let failures = self.dynamic_hook_apply_failures.entry(pid).or_insert(0);
                        *failures = failures.saturating_add(1);
                        if *failures >= Self::DYNAMIC_HOOK_MAX_FAILURES
                            && (*failures).is_multiple_of(Self::DYNAMIC_HOOK_MAX_FAILURES)
                        {
                            Logging::warning(&format!(
                                "[DYNAMIC HOOK] PID {} still failing to apply hooks (count={}, hr=0x{:08X})",
                                pid, failures, hr
                            ));
                        } else {
                            Logging::error(&format!(
                                "[DYNAMIC HOOK] Failed to apply hooks to PID {} (attempt {}/{} hr=0x{:08X}): {}",
                                pid,
                                failures,
                                Self::DYNAMIC_HOOK_MAX_FAILURES,
                                hr,
                                e
                            ));
                        }
                    }
                } else {
                    self.dynamic_hook_apply_failures.remove(&pid);
                    self.dynamic_hook_applied_generation
                        .insert(pid, target_generation);
                }
            }

            self.dynamic_hooks_registered = true;
            Logging::info(&format!(
                "[DYNAMIC HOOK] PID {} => registered={} already={} failed={} wildcard={}",
                pid, registered_count, already_registered_count, failed_count, wildcard_count
            ));
        }
    }
}
