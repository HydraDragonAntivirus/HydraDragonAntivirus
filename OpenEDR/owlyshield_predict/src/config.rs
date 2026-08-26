use configparser::ini::Ini;

use registry::{Hive, Security};
use std::collections::HashMap;
use std::ops::Index;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use strum_macros::EnumIter;

use crate::extensions::ExtensionList;

const SANCTUM_SETTINGS_PATH: &str =
    r"C:\Program Files\HydraDragonAntivirus\hydradragon\Sanctum\AppData\config.cfg";

/// Registry gate (HKLM\SOFTWARE\Owlyshield\TRUST_COMODO_CLOUD = 1) for the
/// Comodo-cloud trust policy: processes the cloud marked Safe are not fully
/// monitored (their API-hook flood and other events skip named-condition rule
/// evaluation) and are never quarantined — only kill is allowed.
static TRUST_COMODO_CLOUD: AtomicBool = AtomicBool::new(false);

/// Read TRUST_COMODO_CLOUD from the Owlyshield registry at startup. Mirrors
/// how VERBOSE_LOGGING is cached in logging.rs so the hot paths never touch
/// the registry.
pub fn init_trust_comodo_cloud() {
    let val = ConfigReader::read_param_from_registry("TRUST_COMODO_CLOUD", r"SOFTWARE\Owlyshield");
    let clean = val.trim_matches('\0').trim().to_lowercase();
    TRUST_COMODO_CLOUD.store(clean == "1" || clean == "true", Ordering::Relaxed);
}

/// Whether the Comodo-cloud trust policy is enabled (default: off).
pub fn is_trust_comodo_cloud_enabled() -> bool {
    TRUST_COMODO_CLOUD.load(Ordering::Relaxed)
}

static MONITOR_ALL_APIS: AtomicBool = AtomicBool::new(false);

pub fn init_monitor_all_apis() {
    let val = ConfigReader::read_param_from_registry("MONITOR_ALL_APIS", r"SOFTWARE\Owlyshield");
    let clean = val.trim_matches('\0').trim().to_lowercase();
    MONITOR_ALL_APIS.store(clean == "1" || clean == "true", Ordering::Relaxed);
}

pub fn is_monitor_all_apis_enabled() -> bool {
    MONITOR_ALL_APIS.load(Ordering::Relaxed)
}

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
    RulesPath,
    StaticRulesPath,
    StaticRulesMode,
    ReportDir,
    SdkPath,
    LogPath,
    VerboseLogging,
    ProcessActivityPath,
    ExtensionSourceMode,
    MinimalScanTimeoutMs,
    DeepScanTimeoutMs,
    LateChildScanGraceMs,
    AlwaysAutoRevert,
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
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "CONFIG_PATH", // incidents reports, exclusions list
            Param::NumVersion => "NUM_VERSION",
            Param::RealTimeLearningPath => "REALTIME_LEARNING_PATH",
            Param::UtilsPath => "UTILS_PATH",   // toast.exe
            Param::AppId => "APP_ID",           // AppUserModelID for toast notifications
            Param::KillPolicy => "KILL_POLICY", // SUSPEND / KILL
            Param::Language => "LANGUAGE",      // Language used at installation
            Param::Telemetry => "TELEMETRY",    // 1 if telemetry is active, 0 if not
            Param::MqttServer => "MQTT_SERVER",
            Param::RulesPath => "RULES_PATH",
            Param::StaticRulesPath => "STATIC_RULES_PATH",
            Param::StaticRulesMode => "STATIC_RULES_MODE",
            Param::ReportDir => "REPORTS_PATH",
            Param::SdkPath => "SDK_PATH",
            Param::LogPath => "LOG_PATH", // Path to log output directory
            Param::VerboseLogging => "VERBOSE_LOGGING", // 1 if verbose logging is active, 0 if not
            Param::ProcessActivityPath => "PROCESS_ACTIVITY_PATH", // Path to process activity debug output
            Param::ExtensionSourceMode => "EXTENSION_SOURCE_MODE", // feedback / extensions_rs_only / extensions_txt_only
            Param::MinimalScanTimeoutMs => "MINIMAL_SCAN_TIMEOUT_MS",
            Param::DeepScanTimeoutMs => "DEEP_SCAN_TIMEOUT_MS",
            Param::LateChildScanGraceMs => "LATE_CHILD_SCAN_GRACE_MS",
            Param::AlwaysAutoRevert => "ALWAYS_AUTO_REVERT",
            _ => "UNKNOWN",
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_to_str(param: &Param) -> &str {
        match param {
            Param::ConfigPath => "config_path", // incidents reports, exclusions list
            Param::NumVersion => "num_version",
            Param::RealTimeLearningPath => "realtime_learning_path",
            Param::UtilsPath => "utils_path",   // toast.exe
            Param::AppId => "app_id",           // AppUserModelID for toast notifications
            Param::KillPolicy => "kill_policy", // SUSPEND / KILL
            Param::Language => "language",      // Language used at installation
            Param::Telemetry => "telemetry",    // 1 if telemetry is active, 0 if not
            Param::MqttServer => "mqtt_server",
            Param::RulesPath => "rules_path",
            Param::StaticRulesPath => "static_rules_path",
            Param::StaticRulesMode => "static_rules_mode",
            Param::ReportDir => "report_dir",
            Param::SdkPath => "sdk_path",
            Param::LogPath => "log_path", // Path to log output directory
            Param::VerboseLogging => "verbose_logging", // 1 if verbose logging is active, 0 if not
            Param::ProcessActivityPath => "process_activity_path", // Path to process activity debug output
            Param::ExtensionSourceMode => "extension_source_mode", // feedback / extensions_rs_only / extensions_txt_only
            Param::MinimalScanTimeoutMs => "minimal_scan_timeout_ms",
            Param::DeepScanTimeoutMs => "deep_scan_timeout_ms",
            Param::LateChildScanGraceMs => "late_child_scan_grace_ms",
            Param::AlwaysAutoRevert => "always_auto_revert",
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
            Param::ExtensionSourceMode,
            Param::MinimalScanTimeoutMs,
            Param::DeepScanTimeoutMs,
            Param::LateChildScanGraceMs,
        ];

        if cfg!(target_os = "windows") {
            params.append(&mut vec![Param::AppId, Param::UtilsPath]);
        }

        params.push(Param::RulesPath);
        params.push(Param::StaticRulesPath);
        params.push(Param::StaticRulesMode);
        params.push(Param::ReportDir);
        params.push(Param::AlwaysAutoRevert);

        let mut ret = Vec::new();
        for param in params {
            let val = Self::convert_to_str(&param).to_string();
            ret.push(val);
        }
        ret
    }

    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "CONFIG_PATH" => Param::ConfigPath, // incidents reports, exclusions list
            "NUM_VERSION" => Param::NumVersion,
            "REALTIME_LEARNING_PATH" => Param::RealTimeLearningPath,
            "UTILS_PATH" => Param::UtilsPath,   // toast.exe
            "APP_ID" => Param::AppId,           // AppUserModelID for toast notifications
            "KILL_POLICY" => Param::KillPolicy, // SUSPEND / KILL
            "LANGUAGE" => Param::Language,      // Language used at installation
            "TELEMETRY" => Param::Telemetry,    // 1 if telemetry is active, 0 if not
            "MQTT_SERVER" => Param::MqttServer,
            "RULES_PATH" => Param::RulesPath,
            "STATIC_RULES_PATH" => Param::StaticRulesPath,
            "STATIC_RULES_MODE" => Param::StaticRulesMode,
            "REPORTS_PATH" => Param::ReportDir,
            "SDK_PATH" => Param::SdkPath,
            "LOG_PATH" => Param::LogPath, // Path to log output directory
            "VERBOSE_LOGGING" => Param::VerboseLogging, // 1 if verbose logging is active, 0 if not
            "PROCESS_ACTIVITY_PATH" => Param::ProcessActivityPath, // Path to process activity debug output
            "EXTENSION_SOURCE_MODE" => Param::ExtensionSourceMode, // feedback / extensions_rs_only / extensions_txt_only
            "MINIMAL_SCAN_TIMEOUT_MS" => Param::MinimalScanTimeoutMs,
            "DEEP_SCAN_TIMEOUT_MS" => Param::DeepScanTimeoutMs,
            "LATE_CHILD_SCAN_GRACE_MS" => Param::LateChildScanGraceMs,
            "ALWAYS_AUTO_REVERT" => Param::AlwaysAutoRevert,
            _ => Param::Unknown,
        }
    }

    #[cfg(target_os = "linux")]
    fn convert_from_str(param: String) -> Param {
        match param.as_str() {
            "config_path" => Param::ConfigPath, // incidents reports, exclusions list
            "num_version" => Param::NumVersion,
            "realtime_learning_path" => Param::RealTimeLearningPath,
            "utils_path" => Param::UtilsPath,   // toast.exe
            "app_id" => Param::AppId,           // AppUserModelID for toast notifications
            "kill_policy" => Param::KillPolicy, // SUSPEND / KILL
            "language" => Param::Language,      // Language used at installation
            "telemetry" => Param::Telemetry,    // 1 if telemetry is active, 0 if not
            "mqtt_server" => Param::MqttServer,
            "rules_path" => Param::RulesPath,
            "static_rules_path" => Param::StaticRulesPath,
            "static_rules_mode" => Param::StaticRulesMode,
            "report_dir" => Param::ReportDir,
            "sdk_path" => Param::SdkPath,
            "log_path" => Param::LogPath, // Path to log output directory
            "verbose_logging" => Param::VerboseLogging, // 1 if verbose logging is active, 0 if not
            "process_activity_path" => Param::ProcessActivityPath, // Path to process activity debug output
            "extension_source_mode" => Param::ExtensionSourceMode, // feedback / extensions_rs_only / extensions_txt_only
            "minimal_scan_timeout_ms" => Param::MinimalScanTimeoutMs,
            "deep_scan_timeout_ms" => Param::DeepScanTimeoutMs,
            "late_child_scan_grace_ms" => Param::LateChildScanGraceMs,
            "always_auto_revert" => Param::AlwaysAutoRevert,
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
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Config {
        Config {
            params: Self::get_params(),
            current_exe: std::env::current_exe().unwrap(),
            extensions_list: ExtensionList::new(),
            threshold_drivermsgs: 70,
            threshold_prediction: 0.55,
            timesteps_stride: 20,
        }
    }

    pub fn model_path(&self, model_name: &str) -> PathBuf {
        let models_dir = self.current_exe.parent().unwrap();
        models_dir.join(Path::new(model_name))
    }

    pub fn get_param(&self, param: Param) -> Option<&str> {
        self.params.get(&param).map(|s| s.as_str())
    }

    fn get_non_empty_param(&self, param: Param) -> Option<&str> {
        self.get_param(param).and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    }

    fn read_sanctum_setting_value(key: &str) -> Option<serde_json::Value> {
        let content = std::fs::read_to_string(SANCTUM_SETTINGS_PATH).ok()?;
        let root: serde_json::Value = serde_json::from_str(&content).ok()?;
        root.get(key).cloned()
    }

    fn parse_u64_setting(value: &str) -> Option<u64> {
        value.trim().parse::<u64>().ok().filter(|v| *v > 0)
    }

    pub fn extension_source_mode(&self) -> Option<String> {
        self.get_non_empty_param(Param::ExtensionSourceMode)
            .map(ToString::to_string)
            .or_else(|| {
                Self::read_sanctum_setting_value("extension_source_mode")
                    .and_then(|value| value.as_str().map(ToString::to_string))
                    .filter(|value| !value.trim().is_empty())
            })
    }

    fn u64_setting(&self, param: Param, sanctum_key: &str, default_value: u64) -> u64 {
        if let Some(value) = self
            .get_non_empty_param(param)
            .and_then(Self::parse_u64_setting)
        {
            return value;
        }

        Self::read_sanctum_setting_value(sanctum_key)
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(Self::parse_u64_setting))
            })
            .filter(|value| *value > 0)
            .unwrap_or(default_value)
    }

    pub fn minimal_scan_timeout_ms(&self, default_value: u64) -> u64 {
        self.u64_setting(
            Param::MinimalScanTimeoutMs,
            "minimal_scan_timeout_ms",
            default_value,
        )
    }

    pub fn deep_scan_timeout_ms(&self, default_value: u64) -> u64 {
        self.u64_setting(
            Param::DeepScanTimeoutMs,
            "deep_scan_timeout_ms",
            default_value,
        )
    }

    pub fn late_child_scan_grace_ms(&self, default_value: u64) -> u64 {
        self.u64_setting(
            Param::LateChildScanGraceMs,
            "late_child_scan_grace_ms",
            default_value,
        )
    }

    pub fn always_auto_revert(&self) -> bool {
        self.get_non_empty_param(Param::AlwaysAutoRevert)
            .map(|val| val.trim() == "1" || val.trim().eq_ignore_ascii_case("true"))
            .or_else(|| {
                Self::read_sanctum_setting_value("always_auto_revert").and_then(|value| {
                    value.as_bool().or_else(|| {
                        value.as_u64().map(|v| v == 1).or_else(|| {
                            value
                                .as_str()
                                .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
                        })
                    })
                })
            })
            .or_else(|| {
                // Fallback: live registry read from HKLM\Software\Owlyshield
                let reg_val = crate::config::ConfigReader::read_param_from_registry(
                    "ALWAYS_AUTO_REVERT",
                    r"SOFTWARE\Owlyshield",
                );
                if reg_val.is_empty() {
                    None
                } else {
                    Some(reg_val.trim() == "1" || reg_val.trim().eq_ignore_ascii_case("true"))
                }
            })
            .unwrap_or(false)
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
        for param in ConfigReader::read_params_from_file(
            Param::get_string_vec(),
            "/etc/owlyshield/owlyshield.conf",
            "owlyshield",
        ) {
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
    pub fn read_param(param: String, location: &str, _bloc: &str) -> String {
        Self::read_param_from_registry(param.as_str(), location)
    }

    #[cfg(target_os = "linux")]
    pub fn read_param(param: String, location: &str, bloc: &str) -> String {
        Self::read_param_from_file(param.as_str(), location, bloc)
    }

    #[allow(dead_code)]
    pub fn read_params(
        params: Vec<String>,
        location: &str,
        _bloc: &str,
    ) -> HashMap<String, String> {
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
                eprintln!(
                    "Registry key '{}' not found in '{}': {}",
                    param, location, e
                );
                String::new()
            }
        }
    }

    #[allow(dead_code)]
    fn read_params_from_file(
        params: Vec<String>,
        location: &str,
        bloc: &str,
    ) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        let mut config = Ini::new();
        let _map = config.load(location);

        for param in params {
            let val = config.get(bloc, param.as_str()).unwrap_or_default();
            ret.insert(param, val);
        }
        ret
    }

    fn read_params_from_registry(params: Vec<String>, location: &str) -> HashMap<String, String> {
        let mut ret: HashMap<String, String> = HashMap::new();
        for param in params {
            let val = Self::read_param_from_registry(param.as_str(), location);
            ret.insert(param, val);
        }
        ret
    }
}
