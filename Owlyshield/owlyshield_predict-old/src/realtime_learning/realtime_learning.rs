//! Real-Time Learning Module
//!
//! Fully automated self-learning system - NO user interaction required
//! - Processes flagged as malicious -> labeled as malware samples
//! - Processes with no malicious activity -> labeled as benign samples
//! - Continuous learning from real-world EDR deployment
//! - All thresholds and parameters adapt automatically

use crate::process::ProcessRecord;
use crate::realtime_learning::api_tracker::ApiTracker;
use crate::realtime_learning::ml_collector::MLCollector;

#[cfg(all(target_os = "windows", feature = "behavior_engine"))]
use crate::behavioral::behavior_engine::{
    AttackStage, BehaviorRule, DetectionLevel, ResponseAction, RuleCondition, RuleStatus,
};

use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};

// Hashing imports
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct QuarantineEntry {
    pub filepath: String,
    pub timestamp: u64,
    pub reason: String,
}

/// Real-time learning configuration - all values adapt automatically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Minimum runtime before considering a process benign (seconds) - adapts based on observed patterns
    pub min_runtime_for_benign: u64,

    /// Minimum operations before considering a process benign - adapts based on observed patterns
    pub min_operations_for_benign: usize,

    /// Auto-save interval (number of samples) - adapts based on system load
    pub auto_save_interval: usize,

    /// Maximum samples to collect before forcing export - adapts based on memory usage
    pub max_samples_buffer: usize,

    /// Enable automatic labeling of benign processes
    pub auto_label_benign: bool,

    /// Confidence threshold for automatic benign labeling (0.0-1.0) - adapts based on false positive rate
    pub benign_confidence_threshold: f32,
}

impl Default for LearningConfig {
    fn default() -> Self {
        LearningConfig {
            min_runtime_for_benign: 60,
            min_operations_for_benign: 50,
            auto_save_interval: 100,
            max_samples_buffer: 1000,
            auto_label_benign: true,
            benign_confidence_threshold: 0.8,
        }
    }
}

/// Process learning state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LearningLabel {
    Unlabeled,
    Malicious,
    Benign,
}

/// Process tracking for real-time learning
#[derive(Debug, Clone)]
pub struct ProcessLearningState {
    pub gid: u64,
    pub process_name: String,
    pub label: LearningLabel,
    pub start_time: SystemTime,
    pub last_activity: SystemTime,
    pub operation_count: usize,
    pub detection_count: usize,
    pub collected: bool,
    pub last_collected_operation_count: usize,
}

/// Real-time learning engine
pub struct RealtimeLearningEngine {
    config: LearningConfig,
    collector: MLCollector,
    process_states: HashMap<u64, ProcessLearningState>,
    #[allow(dead_code)]
    pending_collection: HashSet<u64>,
    stats: LearningStats,
    output_dir: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearningStats {
    pub total_processes_tracked: usize,
    pub malicious_collected: usize,
    pub benign_collected: usize,
    pub auto_labeled_benign: usize,
    pub detections_count: usize,
    pub samples_exported: usize,
}

impl RealtimeLearningEngine {
    pub fn new(output_dir: &str, trusted_signers_path: Option<&str>) -> Self {
        let _ = trusted_signers_path;
        let mut engine = RealtimeLearningEngine {
            config: LearningConfig::default(),
            collector: MLCollector::with_config(
                crate::realtime_learning::ml_collector::CollectionMode::Both,
                std::path::PathBuf::from(output_dir),
                100,
            ),
            process_states: HashMap::new(),
            pending_collection: HashSet::new(),
            stats: LearningStats::default(),
            output_dir: output_dir.to_string(),
        };
        engine.initialize_adaptive_thresholds();
        engine
    }

    fn initialize_adaptive_thresholds(&mut self) {
        self.config.min_runtime_for_benign = 60;
        self.config.min_operations_for_benign = 100;
        self.config.auto_save_interval = 50;
        self.config.max_samples_buffer = 500;
        self.config.benign_confidence_threshold = 0.85;
    }

    pub fn with_config(
        config: LearningConfig,
        output_dir: &str,
        trusted_signers_path: Option<&str>,
    ) -> Self {
        let _ = trusted_signers_path;
        RealtimeLearningEngine {
            collector: MLCollector::with_config(
                crate::realtime_learning::ml_collector::CollectionMode::Both,
                std::path::PathBuf::from(output_dir),
                config.auto_save_interval,
            ),
            config,
            process_states: HashMap::new(),
            pending_collection: HashSet::new(),
            stats: LearningStats::default(),
            output_dir: output_dir.to_string(),
        }
    }

    pub fn track_process(&mut self, gid: u64, process_name: String) {
        match self.process_states.entry(gid) {
            std::collections::hash_map::Entry::Vacant(e) => {
                let state = ProcessLearningState {
                    gid,
                    process_name,
                    label: LearningLabel::Unlabeled,
                    start_time: SystemTime::now(),
                    last_activity: SystemTime::now(),
                    operation_count: 0,
                    detection_count: 0,
                    collected: false,
                    last_collected_operation_count: 0,
                };
                e.insert(state);
                self.stats.total_processes_tracked += 1;
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if !process_name.is_empty()
                    && (e.get().process_name.is_empty() || e.get().process_name.starts_with("gid_"))
                {
                    e.get_mut().process_name = process_name;
                }
            }
        }
    }

    pub fn update_activity(&mut self, gid: u64) {
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.last_activity = SystemTime::now();
            state.operation_count += 1;
            return;
        }

        self.track_process(gid, format!("gid_{gid}"));
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.last_activity = SystemTime::now();
            state.operation_count += 1;
        }
    }

    pub fn mark_detected_malicious(
        &mut self,
        gid: u64,
        api_tracker: &ApiTracker,
        precord: &ProcessRecord,
    ) {
        let process_name = if !precord.appname.trim().is_empty() {
            precord.appname.clone()
        } else if !api_tracker.process_name.trim().is_empty() {
            api_tracker.process_name.clone()
        } else {
            format!("gid_{gid}")
        };
        self.track_process(gid, process_name);

        let mut should_collect = false;
        let mut pname = String::new();

        if let Some(state) = self.process_states.get_mut(&gid) {
            state.detection_count += 1;
            state.label = LearningLabel::Malicious;

            // Keep collecting malicious snapshots as the process keeps doing new work,
            // but avoid duplicate exports from repeated scans of unchanged state.
            if !state.collected || state.operation_count > state.last_collected_operation_count {
                state.collected = true;
                state.last_collected_operation_count = state.operation_count;
                pname = state.process_name.clone();
                should_collect = true;
            }
        }

        if should_collect {
            self.collector.collect_sample(api_tracker, precord, true);
            self.stats.malicious_collected += 1;
            self.stats.detections_count += 1;

            println!(
                "[Real-Time Learning] Collected MALICIOUS sample: {} (GID: {})",
                pname, gid
            );
            self.adapt_thresholds_from_detection();
        }
    }

    fn adapt_thresholds_from_detection(&mut self) {
        if self.stats.detections_count == 0 {
            return;
        }

        let avg_detection_time: u64 = self
            .process_states
            .values()
            .filter(|s| s.detection_count > 0)
            .map(|s| {
                SystemTime::now()
                    .duration_since(s.start_time)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()
            })
            .sum::<u64>()
            / self.stats.detections_count.max(1) as u64;

        if avg_detection_time > 0 && avg_detection_time < self.config.min_runtime_for_benign {
            self.config.min_runtime_for_benign = (avg_detection_time * 2).max(30);
        }
    }

    pub fn check_benign_processes<'a, F>(
        &mut self,
        api_trackers: &HashMap<u64, ApiTracker>,
        get_record: F,
    ) where
        F: Fn(u64) -> Option<&'a ProcessRecord>,
    {
        if !self.config.auto_label_benign {
            return;
        }

        self.adapt_benign_thresholds();

        let now = SystemTime::now();
        let mut to_label_benign = Vec::new();

        for (gid, state) in &self.process_states {
            if state.label != LearningLabel::Unlabeled || state.collected {
                continue;
            }

            let runtime = now
                .duration_since(state.start_time)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            if runtime >= self.config.min_runtime_for_benign
                && state.operation_count >= self.config.min_operations_for_benign
                && state.detection_count == 0
            {
                to_label_benign.push(*gid);
            }
        }

        for gid in to_label_benign {
            let Some(api_tracker) = api_trackers.get(&gid) else {
                continue;
            };
            let Some(precord) = get_record(gid) else {
                continue;
            };

            if let Some(state) = self.process_states.get_mut(&gid) {
                state.label = LearningLabel::Benign;
                state.collected = true;
                let pname = state.process_name.clone();
                self.collector.collect_sample(api_tracker, precord, false);
                self.stats.benign_collected += 1;
                self.stats.auto_labeled_benign += 1;

                println!(
                    "[Real-Time Learning] Auto-labeled BENIGN: {} (GID: {})",
                    pname, gid
                );
            }
        }
    }

    fn adapt_benign_thresholds(&mut self) {
        let unlabeled_processes: Vec<_> = self
            .process_states
            .values()
            .filter(|s| s.label == LearningLabel::Unlabeled && s.detection_count == 0)
            .collect();

        if unlabeled_processes.len() < 10 {
            return;
        }

        let now = SystemTime::now();
        let avg_runtime: u64 = unlabeled_processes
            .iter()
            .map(|s| {
                now.duration_since(s.start_time)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()
            })
            .sum::<u64>()
            / unlabeled_processes.len() as u64;

        let avg_operations: usize = unlabeled_processes
            .iter()
            .map(|s| s.operation_count)
            .sum::<usize>()
            / unlabeled_processes.len();

        if avg_runtime > 0 {
            self.config.min_runtime_for_benign = (avg_runtime * 3 / 4).max(30);
        }
        if avg_operations > 0 {
            self.config.min_operations_for_benign = (avg_operations * 3 / 4).max(50);
        }
    }

    pub fn process_terminated(
        &mut self,
        gid: u64,
        api_tracker: &ApiTracker,
        precord: &ProcessRecord,
    ) {
        let process_name = if !precord.appname.trim().is_empty() {
            precord.appname.clone()
        } else if !api_tracker.process_name.trim().is_empty() {
            api_tracker.process_name.clone()
        } else {
            format!("gid_{gid}")
        };
        self.track_process(gid, process_name);

        let mut collection = None;
        let mut should_clear_state = false;

        if let Some(state) = self.process_states.get_mut(&gid) {
            let is_malicious = precord.is_malicious
                || state.label == LearningLabel::Malicious
                || state.detection_count > 0;

            if state.collected
                && (!is_malicious || state.operation_count <= state.last_collected_operation_count)
            {
                should_clear_state = true;
            } else {
                state.label = if is_malicious {
                    LearningLabel::Malicious
                } else {
                    LearningLabel::Benign
                };
                state.collected = true;
                state.last_collected_operation_count = state.operation_count;
                collection = Some((is_malicious, state.process_name.clone()));
                should_clear_state = true;
            }
        }

        if let Some((is_malicious, pname)) = collection {
            self.collector
                .collect_sample(api_tracker, precord, is_malicious);

            if is_malicious {
                self.stats.malicious_collected += 1;
                self.stats.detections_count += 1;
                println!(
                    "[Real-Time Learning] Process terminated, collected MALICIOUS sample: {} (GID: {})",
                    pname, gid
                );
                self.adapt_thresholds_from_detection();
            } else {
                self.stats.benign_collected += 1;
                self.stats.auto_labeled_benign += 1;
                println!(
                    "[Real-Time Learning] Process terminated, collected BENIGN sample: {} (GID: {})",
                    pname, gid
                );
            }
        }

        if should_clear_state {
            self.clear_process_state(gid);
        }
    }

    pub fn export_samples(&mut self) -> Result<(), std::io::Error> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json_path = format!("{}/realtime_learning_{}.json", self.output_dir, timestamp);
        let csv_path = format!("{}/realtime_learning_{}.csv", self.output_dir, timestamp);
        let yaml_full_path = format!(
            "{}/realtime_learning_full_{}.yaml",
            self.output_dir, timestamp
        );
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        let yaml_path = format!(
            "{}/realtime_learning_rules_{}.yaml",
            self.output_dir, timestamp
        );

        self.collector.export_to_json(&json_path)?;
        self.collector.export_to_csv(&csv_path)?;
        self.collector.export_to_yaml(&yaml_full_path)?;
        #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
        self.collector.export_rules_to_yaml(&yaml_path)?;

        let (mal_count, ben_count) = self.collector.get_counts();
        self.stats.samples_exported += mal_count + ben_count;

        println!(
            "[Real-Time Learning] Exported {} samples (Malicious: {}, Benign: {})",
            mal_count + ben_count,
            mal_count,
            ben_count
        );

        self.collector.clear();
        Ok(())
    }

    pub fn get_stats(&self) -> &LearningStats {
        &self.stats
    }

    pub fn get_process_state(&self, gid: u64) -> Option<&ProcessLearningState> {
        self.process_states.get(&gid)
    }

    pub fn print_stats(&self) {
        println!("\n+--------------------------------------------------------+");
        println!("|        Real-Time Learning Statistics                  |");
        println!("+--------------------------------------------------------+");
        println!(
            "|  Total Processes Tracked: {:6}                      |",
            self.stats.total_processes_tracked
        );
        println!(
            "|  Malicious Collected:     {:6}                      |",
            self.stats.malicious_collected
        );
        println!(
            "|  Benign Collected:        {:6}                      |",
            self.stats.benign_collected
        );
        println!("+--------------------------------------------------------+");
    }

    pub fn should_export(&self) -> bool {
        let (mal, ben) = self.collector.get_counts();
        mal + ben >= self.config.max_samples_buffer
    }

    pub fn clear_process_state(&mut self, gid: u64) {
        self.process_states.remove(&gid);
    }

    pub fn get_config(&self) -> &LearningConfig {
        &self.config
    }

    pub fn update_config(&mut self, config: LearningConfig) {
        self.config = config;
    }

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    pub fn process_quarantine_log(&self, log_path: &Path) -> Vec<BehaviorRule> {
        let mut rules = Vec::new();
        if !log_path.exists() {
            return rules;
        }

        if let Ok(content) = fs::read_to_string(log_path)
            && let Ok(entries) = serde_json::from_str::<Vec<QuarantineEntry>>(&content)
        {
            for entry in entries {
                let path = Path::new(&entry.filepath);
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    let hash_ref = self
                        .calculate_sha256(path)
                        .unwrap_or_else(|| "unknown".to_string());
                    let rule = BehaviorRule {
                        name: format!("AutoBlock_Quarantined_{}", filename),
                        description: format!(
                            "Auto-generated rule for quarantined file. Reason: {}. HWID/Hash Ref: {}",
                            entry.reason, hash_ref
                        ),
                        severity: 100,
                        level: DetectionLevel::Critical,
                        status: RuleStatus::Stable,
                        record_on_start: vec![filename.to_string()],
                        response: ResponseAction {
                            terminate_process: true,
                            quarantine: true,
                            auto_revert: true,
                            ..Default::default()
                        },
                        stages: vec![AttackStage {
                            name: "execution".to_string(),
                            conditions: vec![RuleCondition::Process {
                                op: "Name".to_string(),
                                pattern: filename.to_string(),
                            }],
                        }],
                        ..Default::default()
                    };
                    rules.push(rule);
                }
            }
        }
        rules
    }

    pub fn calculate_sha256(&self, path: &Path) -> Option<String> {
        if let Ok(mut file) = fs::File::open(path) {
            let mut hasher = Sha256::new();
            let mut buffer = [0; 1024];
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buffer[..n]),
                    Err(_) => return None,
                }
            }
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        }
    }

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    pub fn generate_benign_rules(&self) -> Vec<BehaviorRule> {
        Vec::new()
    }

    #[cfg(all(target_os = "windows", feature = "behavior_engine"))]
    pub fn save_rules_to_yaml(&self, rules: &[BehaviorRule], path: &Path) -> std::io::Result<()> {
        if let Ok(file) = std::fs::File::create(path) {
            serde_yaml::to_writer(file, rules).map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::other("Failed to create rule file"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_learning_engine_creation() {
        let engine = RealtimeLearningEngine::new("./test_data", None);
        assert_eq!(engine.stats.total_processes_tracked, 0);
    }

    #[test]
    fn test_process_tracking() {
        let mut engine = RealtimeLearningEngine::new("./test_data", None);
        engine.track_process(1234, "test.exe".to_string());
        assert_eq!(engine.stats.total_processes_tracked, 1);
        assert!(engine.process_states.contains_key(&1234));
    }

    #[test]
    fn test_process_terminated_collects_untracked_benign_sample() {
        let gid = 2345;
        let mut engine = RealtimeLearningEngine::new("./test_data", None);
        let tracker = ApiTracker::new(gid, "benign.exe".to_string());
        let precord = ProcessRecord::new(gid, "benign.exe".to_string(), PathBuf::new());

        engine.process_terminated(gid, &tracker, &precord);

        let (malicious, benign) = engine.collector.get_counts();
        assert_eq!((malicious, benign), (0, 1));
        assert_eq!(engine.stats.benign_collected, 1);
        assert!(engine.process_states.get(&gid).is_none());
    }

    #[test]
    fn test_mark_detected_malicious_collects_without_prior_tracking() {
        let gid = 3456;
        let mut engine = RealtimeLearningEngine::new("./test_data", None);
        let tracker = ApiTracker::new(gid, "malicious.exe".to_string());
        let precord = ProcessRecord::new(gid, "malicious.exe".to_string(), PathBuf::new());

        engine.mark_detected_malicious(gid, &tracker, &precord);

        let (malicious, benign) = engine.collector.get_counts();
        assert_eq!((malicious, benign), (1, 0));
        assert_eq!(engine.stats.malicious_collected, 1);
        assert_eq!(
            engine.process_states.get(&gid).unwrap().label,
            LearningLabel::Malicious
        );
    }

    #[test]
    fn test_mark_detected_malicious_collects_new_activity_snapshots() {
        let gid = 4567;
        let mut engine = RealtimeLearningEngine::new("./test_data", None);
        let tracker = ApiTracker::new(gid, "malicious.exe".to_string());
        let precord = ProcessRecord::new(gid, "malicious.exe".to_string(), PathBuf::new());

        engine.track_process(gid, "malicious.exe".to_string());
        engine.update_activity(gid);
        engine.mark_detected_malicious(gid, &tracker, &precord);
        engine.mark_detected_malicious(gid, &tracker, &precord);

        let (malicious, benign) = engine.collector.get_counts();
        assert_eq!((malicious, benign), (1, 0));

        engine.update_activity(gid);
        engine.mark_detected_malicious(gid, &tracker, &precord);

        let (malicious, benign) = engine.collector.get_counts();
        assert_eq!((malicious, benign), (2, 0));
    }

    #[test]
    fn test_process_terminated_clears_collected_malicious_state() {
        let gid = 5678;
        let mut engine = RealtimeLearningEngine::new("./test_data", None);
        let tracker = ApiTracker::new(gid, "malicious.exe".to_string());
        let mut precord = ProcessRecord::new(gid, "malicious.exe".to_string(), PathBuf::new());
        precord.is_malicious = true;

        engine.track_process(gid, "malicious.exe".to_string());
        engine.update_activity(gid);
        engine.mark_detected_malicious(gid, &tracker, &precord);
        engine.process_terminated(gid, &tracker, &precord);

        let (malicious, benign) = engine.collector.get_counts();
        assert_eq!((malicious, benign), (1, 0));
        assert!(engine.process_states.get(&gid).is_none());
    }
}
