#![cfg(all(target_os = "windows", feature = "hydradragon"))]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use winreg::enums::*;
use winreg::RegKey;

/// Threat action to take when malware is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatAction {
    DoNothing,
    NotifyOnly,
    Suspend,
    DenyAccess,
    Quarantine,
    Kill,
    KillAndQuarantine,
    KillAndRemove,
    AskUser,
}

impl ThreatAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "do_nothing" => ThreatAction::DoNothing,
            "notify_only" => ThreatAction::NotifyOnly,
            "suspend" => ThreatAction::Suspend,
            "deny_access" => ThreatAction::DenyAccess,
            "quarantine" => ThreatAction::Quarantine,
            "kill" => ThreatAction::Kill,
            "kill_and_quarantine" => ThreatAction::KillAndQuarantine,
            "kill_and_remove" => ThreatAction::KillAndRemove,
            "ask_user" => ThreatAction::AskUser,
            _ => ThreatAction::KillAndQuarantine, // Default fallback
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatAction::DoNothing => "do_nothing",
            ThreatAction::NotifyOnly => "notify_only",
            ThreatAction::Suspend => "suspend",
            ThreatAction::DenyAccess => "deny_access",
            ThreatAction::Quarantine => "quarantine",
            ThreatAction::Kill => "kill",
            ThreatAction::KillAndQuarantine => "kill_and_quarantine",
            ThreatAction::KillAndRemove => "kill_and_remove",
            ThreatAction::AskUser => "ask_user",
        }
    }
}

impl Default for ThreatAction {
    fn default() -> Self {
        ThreatAction::KillAndQuarantine
    }
}

/// Detection engine type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionEngine {
    ClamAV,
    Yara,
    YaraX,
    HydraDragonStatic,
    Behavioral,
    PUA,
}

impl DetectionEngine {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "clamav" => Some(DetectionEngine::ClamAV),
            "yara" => Some(DetectionEngine::Yara),
            "yarax" | "yara-x" | "yara_x" => Some(DetectionEngine::YaraX),
            "hydradragonstatic" | "hydradragon_static" => Some(DetectionEngine::HydraDragonStatic),
            "behavioral" => Some(DetectionEngine::Behavioral),
            "pua" => Some(DetectionEngine::PUA),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionEngine::ClamAV => "clamav",
            DetectionEngine::Yara => "yara",
            DetectionEngine::YaraX => "yarax",
            DetectionEngine::HydraDragonStatic => "hydradragonstatic",
            DetectionEngine::Behavioral => "behavioral",
            DetectionEngine::PUA => "pua",
        }
    }

    pub fn all_engines() -> Vec<DetectionEngine> {
        vec![
            DetectionEngine::ClamAV,
            DetectionEngine::Yara,
            DetectionEngine::YaraX,
            DetectionEngine::HydraDragonStatic,
            DetectionEngine::Behavioral,
            DetectionEngine::PUA,
        ]
    }
}

/// Configuration for a specific detection engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub trust_level: u8, // 0-100, where 100 means full trust
    pub action: ThreatAction,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            trust_level: 100, // Full trust by default
            action: ThreatAction::KillAndQuarantine,
        }
    }
}

/// Motor-based threat response settings manager
pub struct ThreatResponseSettings {
    engine_configs: HashMap<DetectionEngine, EngineConfig>,
    registry_key: RegKey,
}

impl ThreatResponseSettings {
    const REGISTRY_PATH: &'static str = r"SOFTWARE\HydraDragonAV\ThreatResponse";

    /// Create a new ThreatResponseSettings instance and load from registry
    pub fn new() -> Result<Self, String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let registry_key = hklm
            .create_subkey(Self::REGISTRY_PATH)
            .map_err(|e| format!("Failed to open/create registry key: {}", e))?
            .0;

        let mut settings = ThreatResponseSettings {
            engine_configs: HashMap::new(),
            registry_key,
        };

        settings.load_from_registry()?;
        Ok(settings)
    }

    /// Load settings from Windows Registry
    fn load_from_registry(&mut self) -> Result<(), String> {
        for engine in DetectionEngine::all_engines() {
            let engine_str = engine.as_str();
            
            // Read trust level (default 100)
            let trust_level: u32 = self
                .registry_key
                .get_value(&format!("{}_trust_level", engine_str))
                .unwrap_or(100);
            
            // Read action (default "kill_and_quarantine")
            let action_str: String = self
                .registry_key
                .get_value(&format!("{}_action", engine_str))
                .unwrap_or_else(|_| "kill_and_quarantine".to_string());

            let config = EngineConfig {
                trust_level: trust_level.min(100) as u8,
                action: ThreatAction::from_str(&action_str),
            };

            self.engine_configs.insert(engine, config);
        }

        Ok(())
    }

    /// Save settings to Windows Registry
    pub fn save_to_registry(&self) -> Result<(), String> {
        for (engine, config) in &self.engine_configs {
            let engine_str = engine.as_str();
            
            self.registry_key
                .set_value(
                    &format!("{}_trust_level", engine_str),
                    &(config.trust_level as u32),
                )
                .map_err(|e| format!("Failed to save trust level for {}: {}", engine_str, e))?;

            self.registry_key
                .set_value(
                    &format!("{}_action", engine_str),
                    &config.action.as_str(),
                )
                .map_err(|e| format!("Failed to save action for {}: {}", engine_str, e))?;
        }

        Ok(())
    }

    /// Get configuration for a specific engine
    pub fn get_engine_config(&self, engine: DetectionEngine) -> EngineConfig {
        self.engine_configs
            .get(&engine)
            .cloned()
            .unwrap_or_default()
    }

    /// Set configuration for a specific engine
    pub fn set_engine_config(&mut self, engine: DetectionEngine, config: EngineConfig) {
        self.engine_configs.insert(engine, config);
    }

    /// Get recommended action for a detection from a specific engine
    pub fn get_recommended_action(&self, engine: DetectionEngine) -> ThreatAction {
        self.get_engine_config(engine).action
    }

    /// Check if detection should be acted upon based on trust level
    pub fn should_act_on_detection(&self, engine: DetectionEngine) -> bool {
        let config = self.get_engine_config(engine);
        config.trust_level >= 50 // Act if trust level is 50% or higher
    }

    /// Get all engine configurations
    pub fn get_all_configs(&self) -> HashMap<DetectionEngine, EngineConfig> {
        self.engine_configs.clone()
    }

    /// Reset all engines to default configuration
    pub fn reset_to_defaults(&mut self) -> Result<(), String> {
        for engine in DetectionEngine::all_engines() {
            self.engine_configs.insert(engine, EngineConfig::default());
        }
        self.save_to_registry()
    }
}

impl Default for ThreatResponseSettings {
    fn default() -> Self {
        let mut engine_configs = HashMap::new();
        for engine in DetectionEngine::all_engines() {
            engine_configs.insert(engine, EngineConfig::default());
        }

        // Create a dummy registry key for default instance
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let registry_key = hklm
            .create_subkey(Self::REGISTRY_PATH)
            .unwrap_or_else(|_| panic!("Failed to create registry key"))
            .0;

        ThreatResponseSettings {
            engine_configs,
            registry_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_action_conversion() {
        assert_eq!(ThreatAction::from_str("kill_and_quarantine"), ThreatAction::KillAndQuarantine);
        assert_eq!(ThreatAction::from_str("KILL_AND_QUARANTINE"), ThreatAction::KillAndQuarantine);
        assert_eq!(ThreatAction::KillAndQuarantine.as_str(), "kill_and_quarantine");
    }

    #[test]
    fn test_detection_engine_conversion() {
        assert_eq!(DetectionEngine::from_str("clamav"), Some(DetectionEngine::ClamAV));
        assert_eq!(DetectionEngine::from_str("yara-x"), Some(DetectionEngine::YaraX));
        assert_eq!(DetectionEngine::ClamAV.as_str(), "clamav");
    }

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.trust_level, 100);
        assert_eq!(config.action, ThreatAction::KillAndQuarantine);
    }
}
