use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppSettings {
    pub behavior_rules_path: PathBuf,
    pub win_verify_trust_path: PathBuf,
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

        Ok(settings)
    }
}
