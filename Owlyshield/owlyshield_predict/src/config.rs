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
    RealTimeLearningPath,
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
    ReportDir,
    SdkPath,
    LogPath,
    VerboseLogging,
    ProcessActivityPath,
    Unknown,
}

#[derive(PartialEq)]
pub enum KillPolicy {
    Suspend,
    Kill,
    KillAndQuarantine,
    KillAndRemove,
    DoNothing,
}

impl Param {
    #[cfg(target_os = "windows")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::RealTimeLearningPath => "REALTIME_LEARNING_PATH",
            Param::UtilsPath => "UTILS_PATH", // toast.exe
            Param::AppId => "APP_ID",         // AppUserModelID for toast notifications
            Param::KillPolicy => "KILL_POLICY", // SUSPEND / KILL
            Param::Language => "LANGUAGE",    // Language used at installation
            Param::Telemetry => "TELEMETRY",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "MQTT_SERVER",
            Param::NoveltyPath => "NOVELTY_PATH",
            Param::RulesPath => "RULES_PATH",
            Param::ReportDir => "REPORTS_PATH",
            Param::SdkPath => "SDK_PATH",
            Param::LogPath => "LOG_PATH",           // Path to log output directory
            Param::VerboseLogging => "VERBOSE_LOGGING", // 1 if verbose logging is active, 0 if not
            Param::ProcessActivityPath => "PROCESS_ACTIVITY_PATH", // Path to process activity debug output
            _ => "UNKNOWN",
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "config_path", // incidents reports, exclusions list
            Param::NumVersion => "num_version",
            Param::RealTimeLearningPath => "realtime_learning_path",
            Param::UtilsPath => "utils_path", // toast.exe
            Param::AppId => "app_id",         // AppUserModelID for toast notifications
            Param::KillPolicy => "kill_policy", // SUSPEND / KILL
            Param::Language => "language",    // Language used at installation
            Param::Telemetry => "telemetry",  // 1 if telemetry is active, 0 if not
            Param::MqttServer => "mqtt_server",
            Param::NoveltyPath => "novelty_path",
            Param::RulesPath => "rules_path",
            Param::ReportDir => "report_dir",
            Param::SdkPath => "sdk_path",
            Param::LogPath => "log_path",           // Path to log output directory
            Param::VerboseLogging => "verbose_logging", // 1 if verbose logging is active, 0 if not
            Param::ProcessActivityPath => "process_activity_path", // Path to process activity debug output
            _ => "unknown",
        }
    }

    fn get_string_vec() -> Vec<String> {
        let mut params = vec![
            Param::KillPolicy,
            Param::ConfigPath,
            Param::Telemetry,
            Param::NumVersion,
            Param::RealTimeLearningPath,
            Param::Language,
            Param::LogPath,
            Param::VerboseLogging,
            Param::ProcessActivityPath,
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
        params.push(Param::ReportDir);

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
            "REALTIME_LEARNING_PATH" => Param::RealTimeLearningPath,
            "UTILS_PATH" => Param::UtilsPath, // toast.exe
            "APP_ID" => Param::AppId,         // AppUserModelID for toast notifications
            "KILL_POLICY" => Param::KillPolicy, // SUSPEND / KILL
            "LANGUAGE" => Param::Language,    // Language used at installation
            "TELEMETRY" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "MQTT_SERVER" => Param::MqttServer,
            "NOVELTY_PATH" => Param::NoveltyPath,
            "RULES_PATH" => Param::RulesPath,
            "REPORTS_PATH" => Param::ReportDir,
            "SDK_PATH" => Param::SdkPath,
            "LOG_PATH" => Param::LogPath,           // Path to log output directory
            "VERBOSE_LOGGING" => Param::VerboseLogging, // 1 if verbose logging is active, 0 if not
            "PROCESS_ACTIVITY_PATH" => Param::ProcessActivityPath, // Path to process activity debug output
            _ => Param::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "config_path" => Param::ConfigPath, // incidents reports, exclusions list
            "num_version" => Param::NumVersion,
            "realtime_learning_path" => Param::RealTimeLearningPath,
            "utils_path" => Param::UtilsPath, // toast.exe
            "app_id" => Param::AppId,         // AppUserModelID for toast notifications
            "kill_policy" => Param::KillPolicy, // SUSPEND / KILL
            "language" => Param::Language,    // Language used at installation
            "telemetry" => Param::Telemetry,  // 1 if telemetry is active, 0 if not
            "mqtt_server" => Param::MqttServer,
            "novelty_path" => Param::NoveltyPath,
            "rules_path" => Param::RulesPath,
            "report_dir" => Param::ReportDir,
            "sdk_path" => Param::SdkPath,
            "log_path" => Param::LogPath,           // Path to log output directory
            "verbose_logging" => Param::VerboseLogging, // 1 if verbose logging is active, 0 if not
            "process_activity_path" => Param::ProcessActivityPath, // Path to process activity debug output
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

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Config {
        #[cfg(feature = "realtime_learning")]
        let mut config = Config {
            params: Self::get_params(),
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 70,
            threshold_prediction: 0.55,
            timesteps_stride: 20,
            adaptive_state: AdaptiveThresholdState::default(),
        };
        #[cfg(not(feature = "realtime_learning"))]
        let config = Config {
            params: Self::get_params(),
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 70,
            threshold_prediction: 0.55,
            timesteps_stride: 20,
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
        if self.adaptive_state.sample_count.is_multiple_of(100) || self.adaptive_state.sample_count == 50 {
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
        let mut sorted_msgs = self.adaptive_state.observed_driver_msg_counts.clone();
        sorted_msgs.sort();
        let p75_idx = (sorted_msgs.len() * 3 / 4).min(sorted_msgs.len() - 1);
        self.threshold_drivermsgs = sorted_msgs[p75_idx].max(30);

        let mut sorted_preds = self.adaptive_state.observed_predictions.clone();
        sorted_preds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p75_idx = (sorted_preds.len() * 3 / 4).min(sorted_preds.len() - 1);
        self.threshold_prediction = sorted_preds[p75_idx].max(0.4).min(0.9);

        let mut sorted_strides = self.adaptive_state.observed_timesteps.clone();
        sorted_strides.sort();
        let p75_idx = (sorted_strides.len() * 3 / 4).min(sorted_strides.len() - 1);
        self.timesteps_stride = sorted_strides[p75_idx].max(5).min(50);

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

    pub fn get_param(&self, param: Param) -> Option<&str> {
        self.params.get(&param).map(|s| s.as_str())
    }

    pub fn get_kill_policy(&self) -> KillPolicy {
        match self[Param::KillPolicy].as_str() {
            "KILL" => KillPolicy::Kill,
            "KILL_AND_QUARANTINE" => KillPolicy::KillAndQuarantine,
            "KILL_AND_REMOVE" => KillPolicy::KillAndRemove,
            "SUSPEND" => KillPolicy::Suspend,
            &_ => KillPolicy::DoNothing,
        }
    }

    #[cfg(target_os = "windows")]
    fn get_params() -> HashMap<Param, String> {
        let mut params: HashMap<Param, String> = HashMap::new();
        let param_names = Param::get_string_vec();
        
        // Use the trusted Registry path ONLY. No fallbacks.
        let location = r"SOFTWARE\Owlyshield";
        let found = ConfigReader::read_params_from_registry(param_names, location);
        
        for (name, val) in found {
            params.insert(Param::convert_from_str(name), val);
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

pub struct ConfigReader {}

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
    pub fn read_param_from_file(param: &str, location: &str, bloc: &str) -> String {
        let mut config = Ini::new();
        let _map = config.load(location);
        config.get(bloc, param).unwrap_or_default()
    }

    #[cfg(target_os = "windows")]
    pub fn read_param_from_registry(param: &str, location: &str) -> String {
        let regkey = match Hive::LocalMachine.open(location, Security::Read) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("Cannot open registry hive '{}': {}", location, e);
                return String::new();
            }
        };
        match regkey.value(param) {
            Ok(val) => val.to_string(),
            Err(e) => {
                eprintln!("Registry key '{}' not found in '{}': {}", param, location, e);
                String::new()
            }
        }
    }

    #[allow(dead_code)]
    fn read_params_from_file(params: Vec<String>, location: &str, bloc: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        let mut config = Ini::new();
        let _map = config.load(location);

        for param in params {
            let val = config.get(bloc, param.as_str()).unwrap_or_default();
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
