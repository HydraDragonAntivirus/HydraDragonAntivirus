use std::collections::HashMap;
use std::ops::Index;
use std::path::{Path, PathBuf};
use configparser::ini::Ini;
#[cfg(target_os = "windows")]
use registry::{Hive, Security};
use strum_macros::EnumIter;

use crate::extensions::ExtensionList;

#[derive(Debug, EnumIter, PartialEq, Eq, Hash, Clone)]
pub enum Param {
    ProcessActivityLogPath,
    ConfigPath,
    NumVersion,
    UtilsPath,
    AppId,
    KillPolicy,
    Language,
    Telemetry,
    MqttServer,
    NoveltyPath,
    RulesPath,
    Unknown,
}

#[derive(PartialEq)]
pub enum KillPolicy {
    Suspend,
    Kill,
    DoNothing,
}

impl Param {
    #[cfg(target_os = "windows")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::ProcessActivityLogPath => "PROCESS_ACTIVITY_PATH", // dir with prediction.csv (used for debug)
            Param::UtilsPath => "UTILS_PATH", // toast.exe
            Param::AppId => "APP_ID",         // AppUserModelID for toast notifications
            Param::KillPolicy => "KILL_POLICY", // SUSPEND / KILL
            Param::Language => "LANGUAGE",    // Language used at installation
            Param::Telemetry => "TELEMETRY",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "MQTT_SERVER",
            Param::NoveltyPath => "NOVELTY_PATH",
            Param::RulesPath => "RULES_PATH",
            _ => "UNKNOWN"
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "config_path", // incidents reports, exclusions list
            Param::NumVersion => "num_version",
            Param::ProcessActivityLogPath => "process_activity_path", // dir with prediction.csv (used for debug)
            Param::UtilsPath => "utils_path", // toast.exe
            Param::AppId => "app_id",         // AppUserModelID for toast notifications
            Param::KillPolicy => "kill_policy", // SUSPEND / KILL
            Param::Language => "language",    // Language used at installation
            Param::Telemetry => "telemetry",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "mqtt_server",
            Param::NoveltyPath => "novelty_path",
            Param::RulesPath => "rules_path",
            _ => "unknown"
        }
    }

    fn get_string_vec() -> Vec<String> {
        let mut params = vec![
            Param::KillPolicy,
            Param::ConfigPath,
            Param::Telemetry,
            Param::NumVersion,
            Param::ProcessActivityLogPath,
            Param::Language,
        ];

        if cfg!(target_os = "windows") {
            params.append(&mut vec![
                Param::AppId,
                Param::UtilsPath,
            ]);
        }
        if cfg!(feature = "mqtt") {
            params.push(Param::MqttServer);
        }

        if cfg!(feature = "novelty") {
            params.push(Param::NoveltyPath);
        }

        params.push(Param::RulesPath);

        let mut ret = Vec::new();
        for param in params {
            let val = Self::convert_to_str(&param).to_string();
            ret.push(val);
        }
        ret
    }

    #[cfg(target_os = "windows")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "CONFIG_PATH" => Param::ConfigPath, // incidents reports, exclusions list
            "NUM_VERSION" => Param::NumVersion,
            "PROCESS_ACTIVITY_PATH" => Param::ProcessActivityLogPath, // dir with prediction.csv (used for debug)
            "UTILS_PATH" => Param::UtilsPath, // toast.exe
            "APP_ID" => Param::AppId,         // AppUserModelID for toast notifications
            "KILL_POLICY" => Param::KillPolicy, // SUSPEND / KILL
            "LANGUAGE" => Param::Language,    // Language used at installation
            "TELEMETRY" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "MQTT_SERVER" => Param::MqttServer,
            "NOVELTY_PATH" => Param::NoveltyPath,
            "RULES_PATH" => Param::RulesPath,
            _ => Param::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "config_path" => Param::ConfigPath, // incidents reports, exclusions list
            "num_version" => Param::NumVersion,
            "process_activity_path" => Param::ProcessActivityLogPath, // dir with prediction.csv (used for debug)
            "utils_path" => Param::UtilsPath, // toast.exe
            "app_id" => Param::AppId,         // AppUserModelID for toast notifications
            "kill_policy" => Param::KillPolicy, // SUSPEND / KILL
            "language" => Param::Language,    // Language used at installation
            "telemetry" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "mqtt_server" => Param::MqttServer,
            "novelty_path" => Param::NoveltyPath,
            "rules_path" => Param::RulesPath,
            _ => Param::Unknown,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    params: HashMap<Param, String>,
    current_exe: PathBuf,
    pub extensions_list: ExtensionList,
    pub threshold_drivermsgs: usize,
    pub threshold_prediction: f32,
    pub timesteps_stride: usize,
    // Adaptive learning state (realtime_learning feature)
    #[cfg(feature = "realtime_learning")]
    adaptive_state: AdaptiveThresholdState,
}

#[cfg(feature = "realtime_learning")]
#[derive(Debug, Default)]
struct AdaptiveThresholdState {
    observed_driver_msg_counts: Vec<usize>,
    observed_predictions: Vec<f32>,
    observed_timesteps: Vec<usize>,
    sample_count: usize,
}

impl Config {
    pub fn new() -> Config {
        let mut config = Config {
            params: Self::get_params(),
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 70,
            threshold_prediction: 0.55,
            timesteps_stride: 20,
            #[cfg(feature = "realtime_learning")]
            adaptive_state: AdaptiveThresholdState::default(),
        };
        // Initialize with minimal values that will adapt quickly (realtime_learning feature)
        #[cfg(feature = "realtime_learning")]
        {
            config.initialize_adaptive_thresholds();
        }
        config
    }

    #[cfg(feature = "realtime_learning")]
    /// Initialize adaptive thresholds with conservative starting values
    fn initialize_adaptive_thresholds(&mut self) {
        // Start with minimal values - will adapt based on observed patterns
        self.threshold_drivermsgs = 50;  // Start low, will adapt up
        self.threshold_prediction = 0.5;  // Start at 50%, will adapt based on false positive rate
        self.timesteps_stride = 10;  // Start small, will adapt based on system performance
    }

    #[cfg(feature = "realtime_learning")]
    /// Adapt thresholds based on observed behavior (self-learning)
    pub fn adapt_thresholds(&mut self, driver_msg_count: usize, prediction: f32, timesteps: usize) {
        self.adaptive_state.observed_driver_msg_counts.push(driver_msg_count);
        self.adaptive_state.observed_predictions.push(prediction);
        self.adaptive_state.observed_timesteps.push(timesteps);
        self.adaptive_state.sample_count += 1;
        
        // Adapt every 100 samples or when we have enough data
        if self.adaptive_state.sample_count % 100 == 0 || self.adaptive_state.sample_count == 50 {
            self.update_adaptive_thresholds();
        }
    }

    #[cfg(feature = "realtime_learning")]
    /// Update thresholds based on statistical analysis of observed data
    fn update_adaptive_thresholds(&mut self) {
        if self.adaptive_state.observed_driver_msg_counts.len() < 10 {
            return;  // Need more data
        }
        
        // Calculate percentile-based thresholds (75th percentile)
        // This ensures we catch most cases while avoiding false positives
        let mut sorted_msgs = self.adaptive_state.observed_driver_msg_counts.clone();
        sorted_msgs.sort();
        let p75_idx = (sorted_msgs.len() * 3 / 4).min(sorted_msgs.len() - 1);
        self.threshold_drivermsgs = sorted_msgs[p75_idx].max(30);  // Min 30
        
        // Adapt prediction threshold based on observed prediction distribution
        let mut sorted_preds = self.adaptive_state.observed_predictions.clone();
        sorted_preds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p75_idx = (sorted_preds.len() * 3 / 4).min(sorted_preds.len() - 1);
        self.threshold_prediction = sorted_preds[p75_idx].max(0.4).min(0.9);  // Between 40% and 90%
        
        // Adapt timesteps stride based on observed patterns
        let mut sorted_strides = self.adaptive_state.observed_timesteps.clone();
        sorted_strides.sort();
        let p75_idx = (sorted_strides.len() * 3 / 4).min(sorted_strides.len() - 1);
        self.timesteps_stride = sorted_strides[p75_idx].max(5).min(50);  // Between 5 and 50
        
        // Keep only recent samples to allow continuous adaptation
        if self.adaptive_state.observed_driver_msg_counts.len() > 1000 {
            self.adaptive_state.observed_driver_msg_counts.drain(0..500);
            self.adaptive_state.observed_predictions.drain(0..500);
            self.adaptive_state.observed_timesteps.drain(0..500);
        }
    }

    pub fn model_path(&self, model_name: &str) -> PathBuf {
        let models_dir = self.current_exe.parent().unwrap();
        models_dir.join(Path::new(model_name))
    }

    pub fn get_kill_policy(&self) -> KillPolicy {
        match self[Param::KillPolicy].as_str() {
            "KILL" => KillPolicy::Kill,
            "SUSPEND" => KillPolicy::Suspend,
            &_ => KillPolicy::DoNothing,
        }
    }

    #[cfg(target_os = "windows")]
    fn get_params() -> HashMap<Param, String> {
        let mut params: HashMap<Param, String> = HashMap::new();
        for param in ConfigReader::read_params_from_registry(Param::get_string_vec(), r"SOFTWARE\Owlyshield") {
            params.insert(Param::convert_from_str(param.0), param.1);
        }
        params
    }

    #[cfg(target_os = "linux")]
    fn get_params() -> HashMap<Param, String> {
        let mut params: HashMap<Param, String> = HashMap::new();
        for param in ConfigReader::read_params_from_file(Param::get_string_vec(), "/etc/owlyshield/owlyshield.conf", "owlyshield") {
            params.insert(Param::convert_from_str(param.0), param.1);
        }
        params
    }
}

impl Index<Param> for Config {
    type Output = String;

    fn index(&self, index: Param) -> &Self::Output {
        &self.params[&index]
    }
}

pub struct ConfigReader {
    // location: String,
}

impl ConfigReader {

    #[cfg(target_os = "windows")]
    pub fn read_param(param: String, location: &str, _bloc: &str) -> String {
        Self::read_param_from_registry(param.as_str(), location)
    }

    #[cfg(target_os = "linux")]
    pub fn read_param(param: String, location: &str, bloc: &str) -> String {
        Self::read_param_from_file(param.as_str(), location, bloc)
    }

    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    pub fn read_params(params: Vec<String>, location: &str, _bloc: &str) -> HashMap<String, String> {
        Self::read_params_from_registry(params, location)
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub fn read_params(params: Vec<String>, location: &str, bloc: &str) -> HashMap<String, String> {
        Self::read_params_from_file(params, location, bloc)
    }

    #[allow(dead_code)]
    pub fn read_param_from_file(param: &str, location: &str, bloc: &str) -> String  {
        //"/etc/owlyshield/owlyshield.conf"
        let mut config = Ini::new();
        let _map = config.load(location);
        config.get(bloc, param).unwrap()
    }

    #[cfg(target_os = "windows")]
    pub fn read_param_from_registry(param: &str, location: &str) -> String  {
        let regkey = Hive::LocalMachine
            .open(location, Security::Read)
            .expect("Cannot open registry hive");
        regkey
            .value(param)
            .unwrap_or_else(|_| panic!("Cannot open registry key {param:?}"))
            .to_string()
    }

    #[allow(dead_code)]
    fn read_params_from_file(params: Vec<String>, location: &str, bloc: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        let mut config = Ini::new();
        let _map = config.load(location);

        for param in params {
            let val = config.get(bloc, param.as_str()).unwrap();
            ret.insert(param, val);
        }
        ret
    }

    #[cfg(target_os = "windows")]
    fn read_params_from_registry(params: Vec<String>, location: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        for param in params {
            let val = Self::read_param_from_registry(param.as_str(), location);
            ret.insert(param, val);
        }
        ret
    }
}
