use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppSettings {
    pub behavior_rules_path: PathBuf,
    pub win_verify_trust_path: PathBuf,
    /// Global process exclusions (glob patterns matched against the
    /// canonicalized process path). Processes matching any pattern are never
    /// evaluated by ANY behavior rule. Intended for the product's own
    /// components so the engine can not flag itself.
    #[serde(default)]
    pub excluded_processes: Vec<String>,
}

impl AppSettings {
    pub fn load(rules_dir: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let settings_path = rules_dir.join("settings.yaml");
        let settings_content = fs::read_to_string(&settings_path)?;
        let mut settings: AppSettings = serde_yaml::from_str(&settings_content)?;

        // Resolve relative paths against rules_dir
        if settings.behavior_rules_path.is_relative() {
            settings.behavior_rules_path = rules_dir.join(&settings.behavior_rules_path);
        }

        if settings.win_verify_trust_path.is_relative() {
            settings.win_verify_trust_path = rules_dir.join(&settings.win_verify_trust_path);
        }

        crate::globals::EXCLUDED_PROCESSES
            .set(settings.excluded_processes.clone())
            .ok();

        Ok(settings)
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            behavior_rules_path: PathBuf::new(),
            win_verify_trust_path: PathBuf::new(),
            excluded_processes: Vec::new(),
        }
    }
}
