use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    pub fn display_name(&self) -> &'static str {
        match self {
            ThreatAction::DoNothing => "Do Nothing",
            ThreatAction::NotifyOnly => "Notify Only",
            ThreatAction::Suspend => "Suspend Process",
            ThreatAction::DenyAccess => "Deny Access",
            ThreatAction::Quarantine => "Quarantine File",
            ThreatAction::Kill => "Kill Process",
            ThreatAction::KillAndQuarantine => "Kill & Quarantine",
            ThreatAction::KillAndRemove => "Kill & Remove",
            ThreatAction::AskUser => "Ask User",
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

    pub fn display_name(&self) -> &'static str {
        match self {
            DetectionEngine::ClamAV => "ClamAV",
            DetectionEngine::Yara => "YARA",
            DetectionEngine::YaraX => "YARA-X",
            DetectionEngine::HydraDragonStatic => "HydraDragon Static",
            DetectionEngine::Behavioral => "Behavioral Analysis",
            DetectionEngine::PUA => "PUA Detection",
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Threat response settings
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatResponseSettings {
    pub engine_configs: HashMap<String, EngineConfig>,
}

impl ThreatResponseSettings {
    pub fn new() -> Self {
        let mut engine_configs = HashMap::new();
        for engine in DetectionEngine::all_engines() {
            engine_configs.insert(engine.as_str().to_string(), EngineConfig::default());
        }
        ThreatResponseSettings { engine_configs }
    }

    /// Get configuration for a specific engine
    pub fn get_engine_config(&self, engine: DetectionEngine) -> EngineConfig {
        self.engine_configs
            .get(engine.as_str())
            .cloned()
            .unwrap_or_default()
    }

    /// Set configuration for a specific engine
    pub fn set_engine_config(&mut self, engine: DetectionEngine, config: EngineConfig) {
        self.engine_configs.insert(engine.as_str().to_string(), config);
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

    /// Reset all engines to default configuration
    pub fn reset_to_defaults(&mut self) {
        for engine in DetectionEngine::all_engines() {
            self.engine_configs.insert(engine.as_str().to_string(), EngineConfig::default());
        }
    }
}

impl Default for ThreatResponseSettings {
    fn default() -> Self {
        Self::new()
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
