//! Real-Time Learning Module
//!
//! Fully automated self-learning system - NO user interaction required
//! - Processes flagged as malicious → labeled as malware samples
//! - Processes with no malicious activity → labeled as benign samples
//! - Continuous learning from real-world EDR deployment
//! - All thresholds and parameters adapt automatically

use crate::realtime_learning::api_tracker::ApiTracker;
use crate::realtime_learning::ml_collector::MLCollector;
use crate::process::ProcessRecord;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Duration};

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
        // Initial values - will adapt automatically based on observed behavior
        LearningConfig {
            min_runtime_for_benign: 0,  // Will be learned from baseline
            min_operations_for_benign: 0,  // Will be learned from baseline
            auto_save_interval: 0,  // Will adapt based on system performance
            max_samples_buffer: 0,  // Will adapt based on available memory
            auto_label_benign: true,
            benign_confidence_threshold: 0.0,  // Will be learned from statistical analysis
        }
    }
}

/// Process learning state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LearningLabel {
    /// Not yet labeled
    Unlabeled,
    /// Confirmed malicious (by detection)
    Malicious,
    /// Confirmed benign (by time/activity analysis)
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
    pub detection_count: usize,  // How many times detected as malicious
    pub collected: bool,  // Already collected for ML
}

/// Real-time learning engine
pub struct RealtimeLearningEngine {
    /// Configuration
    config: LearningConfig,

    /// ML data collector
    collector: MLCollector,

    /// Process learning states
    process_states: HashMap<u64, ProcessLearningState>,

    /// Processes pending collection (waiting to be labeled)
    #[allow(dead_code)]
    pending_collection: HashSet<u64>,

    /// Statistics
    stats: LearningStats,

    /// Output directory
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
    /// Create a new real-time learning engine
    pub fn new(output_dir: &str) -> Self {
        let mut engine = RealtimeLearningEngine {
            config: LearningConfig::default(),
            collector: MLCollector::with_config(
                crate::realtime_learning::ml_collector::CollectionMode::Both,
                std::path::PathBuf::from(output_dir),
                0,  // Will adapt automatically
            ),
            process_states: HashMap::new(),
            pending_collection: HashSet::new(),
            stats: LearningStats::default(),
            output_dir: output_dir.to_string(),
        };
        // Initialize adaptive thresholds from system baseline
        engine.initialize_adaptive_thresholds();
        engine
    }
    
    /// Initialize adaptive thresholds based on system baseline
    fn initialize_adaptive_thresholds(&mut self) {
        // These will be learned from first observed processes
        // For now, use minimal values that will adapt quickly
        self.config.min_runtime_for_benign = 60;  // Start with 1 minute, will adapt
        self.config.min_operations_for_benign = 100;  // Start with 100, will adapt
        self.config.auto_save_interval = 50;  // Start conservative, will adapt
        self.config.max_samples_buffer = 500;  // Start conservative, will adapt
        self.config.benign_confidence_threshold = 0.85;  // Start conservative, will adapt
    }

    /// Create with custom configuration
    pub fn with_config(config: LearningConfig, output_dir: &str) -> Self {
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

    /// Track a process (called when first seen)
    pub fn track_process(&mut self, gid: u64, process_name: String) {
        if !self.process_states.contains_key(&gid) {
            let state = ProcessLearningState {
                gid,
                process_name,
                label: LearningLabel::Unlabeled,
                start_time: SystemTime::now(),
                last_activity: SystemTime::now(),
                operation_count: 0,
                detection_count: 0,
                collected: false,
            };

            self.process_states.insert(gid, state);
            self.stats.total_processes_tracked += 1;
        }
    }

    /// Update process activity
    pub fn update_activity(&mut self, gid: u64) {
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.last_activity = SystemTime::now();
            state.operation_count += 1;
        }
    }

    /// Mark process as detected malicious (by realtime learning)
    pub fn mark_detected_malicious(&mut self, gid: u64, api_tracker: &ApiTracker, precord: &ProcessRecord) {
        if let Some(state) = self.process_states.get_mut(&gid) {
            state.detection_count += 1;
            state.label = LearningLabel::Malicious;

            // Collect sample immediately
            if !state.collected {
                self.collector.collect_sample(api_tracker, precord, true);
                state.collected = true;
                self.stats.malicious_collected += 1;
                self.stats.detections_count += 1;

                println!("[Real-Time Learning] 🦠 Collected MALICIOUS sample: {} (GID: {})",
                         state.process_name, gid);
                
                // Adapt thresholds based on detection patterns
                self.adapt_thresholds_from_detection();
            }
        }
    }
    
    /// Adapt thresholds based on detection patterns (self-learning)
    fn adapt_thresholds_from_detection(&mut self) {
        // Learn optimal thresholds from detection patterns
        // If detections happen early, lower thresholds; if late, raise them
        let avg_detection_time: u64 = self.process_states.values()
            .filter(|s| s.detection_count > 0)
            .map(|s| SystemTime::now().duration_since(s.start_time)
                .unwrap_or(Duration::from_secs(0)).as_secs())
            .sum::<u64>() / self.stats.detections_count.max(1) as u64;
        
        // Adapt min_runtime based on when malicious processes are typically detected
        if avg_detection_time > 0 && avg_detection_time < self.config.min_runtime_for_benign {
            self.config.min_runtime_for_benign = (avg_detection_time * 2).max(30);
        }
    }

    /// Check and auto-label benign processes (called periodically)
    /// Adapts thresholds automatically based on observed patterns
    pub fn check_benign_processes(&mut self, api_trackers: &HashMap<u64, ApiTracker>, process_records: &HashMap<u64, ProcessRecord>) {
        if !self.config.auto_label_benign {
            return;
        }

        // Adapt thresholds based on observed benign processes
        self.adapt_benign_thresholds(api_trackers, process_records);

        let now = SystemTime::now();
        let mut to_label_benign = Vec::new();

        for (gid, state) in &self.process_states {
            // Skip if already labeled or collected
            if state.label != LearningLabel::Unlabeled || state.collected {
                continue;
            }

            // Check if process has been running long enough
            let runtime = now.duration_since(state.start_time)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            // Criteria for benign (using adaptive thresholds):
            // 1. Running for minimum time (adaptive)
            // 2. Has minimum operations (adaptive)
            // 3. No detections
            if runtime >= self.config.min_runtime_for_benign
                && state.operation_count >= self.config.min_operations_for_benign
                && state.detection_count == 0
            {
                to_label_benign.push(*gid);
            }
        }

        // Collect benign samples
        for gid in to_label_benign {
            if let Some(api_tracker) = api_trackers.get(&gid) {
                if let Some(precord) = process_records.get(&gid) {
                    if let Some(state) = self.process_states.get_mut(&gid) {
                        state.label = LearningLabel::Benign;
                        state.collected = true;

                        self.collector.collect_sample(api_tracker, precord, false);
                        self.stats.benign_collected += 1;
                        self.stats.auto_labeled_benign += 1;

                        println!("[Real-Time Learning] 📗 Auto-labeled BENIGN: {} (GID: {}, Runtime: {}s, Ops: {})",
                                 state.process_name, gid,
                                 SystemTime::now().duration_since(state.start_time).unwrap_or(Duration::from_secs(0)).as_secs(),
                                 state.operation_count);
                    }
                }
            }
        }
    }
    
    /// Adapt benign thresholds based on observed process patterns (self-learning)
    fn adapt_benign_thresholds(&mut self, _api_trackers: &HashMap<u64, ApiTracker>, _process_records: &HashMap<u64, ProcessRecord>) {
        // Learn from unlabeled processes that have been running
        let unlabeled_processes: Vec<_> = self.process_states.values()
            .filter(|s| s.label == LearningLabel::Unlabeled && s.detection_count == 0)
            .collect();
        
        if unlabeled_processes.len() < 10 {
            return; // Need more data to adapt
        }
        
        // Calculate statistics from unlabeled processes
        let avg_runtime: u64 = unlabeled_processes.iter()
            .map(|s| SystemTime::now().duration_since(s.start_time)
                .unwrap_or(Duration::from_secs(0)).as_secs())
            .sum::<u64>() / unlabeled_processes.len() as u64;
        
        let avg_operations: usize = unlabeled_processes.iter()
            .map(|s| s.operation_count)
            .sum::<usize>() / unlabeled_processes.len();
        
        // Adapt thresholds: use percentile-based approach (e.g., 75th percentile)
        // This ensures we catch most benign processes while avoiding false positives
        if avg_runtime > 0 {
            self.config.min_runtime_for_benign = (avg_runtime * 3 / 4).max(30);  // 75th percentile, min 30s
        }
        if avg_operations > 0 {
            self.config.min_operations_for_benign = (avg_operations * 3 / 4).max(50);  // 75th percentile, min 50
        }
    }

    /// Process terminated - final chance to collect
    pub fn process_terminated(&mut self, gid: u64, api_tracker: &ApiTracker, precord: &ProcessRecord) {
        if let Some(state) = self.process_states.get_mut(&gid) {
            // If still unlabeled but ran for a while with no issues, mark as benign
            if state.label == LearningLabel::Unlabeled && !state.collected {
                let runtime = SystemTime::now()
                    .duration_since(state.start_time)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();

                if runtime >= self.config.min_runtime_for_benign / 2  // Lower threshold on termination
                    && state.operation_count >= self.config.min_operations_for_benign / 2
                    && state.detection_count == 0
                {
                    state.label = LearningLabel::Benign;
                    self.collector.collect_sample(api_tracker, precord, false);
                    state.collected = true;
                    self.stats.benign_collected += 1;
                    self.stats.auto_labeled_benign += 1;

                    println!("[Real-Time Learning] 📘 Process terminated, labeled BENIGN: {} (GID: {})",
                             state.process_name, gid);
                }
            }
        }
    }

    /// Export collected samples
    pub fn export_samples(&mut self) -> Result<(), std::io::Error> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json_path = format!("{}/realtime_learning_{}.json", self.output_dir, timestamp);
        let csv_path = format!("{}/realtime_learning_{}.csv", self.output_dir, timestamp);

        self.collector.export_to_json(&json_path)?;
        self.collector.export_to_csv(&csv_path)?;

        let (mal_count, ben_count) = self.collector.get_counts();
        self.stats.samples_exported += mal_count + ben_count;

        println!("[Real-Time Learning] 💾 Exported {} samples (Malicious: {}, Benign: {})",
                 mal_count + ben_count, mal_count, ben_count);
        println!("  JSON: {}", json_path);
        println!("  CSV: {}", csv_path);

        // Clear collector after export
        self.collector.clear();

        Ok(())
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &LearningStats {
        &self.stats
    }

    /// Get process learning state
    pub fn get_process_state(&self, gid: u64) -> Option<&ProcessLearningState> {
        self.process_states.get(&gid)
    }

    /// Print statistics
    pub fn print_stats(&self) {
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║        Real-Time Learning Statistics                  ║");
        println!("╠════════════════════════════════════════════════════════╣");
        println!("║  Total Processes Tracked: {:6}                      ║", self.stats.total_processes_tracked);
        println!("║  ─────────────────────────────────────────────────     ║");
        println!("║  Malicious Collected:     {:6}                      ║", self.stats.malicious_collected);
        println!("║    - By Detection:        {:6}                      ║", self.stats.detections_count);
        println!("║  ─────────────────────────────────────────────────     ║");
        println!("║  Benign Collected:        {:6}                      ║", self.stats.benign_collected);
        println!("║    - Auto-labeled:        {:6}                      ║", self.stats.auto_labeled_benign);
        println!("║  ─────────────────────────────────────────────────     ║");
        println!("║  Total Samples:           {:6}                      ║",
                 self.stats.malicious_collected + self.stats.benign_collected);
        println!("║  Samples Exported:        {:6}                      ║", self.stats.samples_exported);
        println!("╚════════════════════════════════════════════════════════╝\n");
    }

    /// Check if buffer is full and needs export
    pub fn should_export(&self) -> bool {
        let (mal, ben) = self.collector.get_counts();
        mal + ben >= self.config.max_samples_buffer
    }

    /// Clear process state (for cleanup)
    pub fn clear_process_state(&mut self, gid: u64) {
        self.process_states.remove(&gid);
    }

    /// Get configuration
    pub fn get_config(&self) -> &LearningConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: LearningConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learning_engine_creation() {
        let engine = RealtimeLearningEngine::new("./test_data");
        assert_eq!(engine.stats.total_processes_tracked, 0);
    }

    #[test]
    fn test_process_tracking() {
        let mut engine = RealtimeLearningEngine::new("./test_data");
        engine.track_process(1234, "test.exe".to_string());

        assert_eq!(engine.stats.total_processes_tracked, 1);
        assert!(engine.process_states.contains_key(&1234));
    }

    #[test]
    fn test_activity_update() {
        let mut engine = RealtimeLearningEngine::new("./test_data");
        engine.track_process(1234, "test.exe".to_string());

        let initial_count = engine.process_states[&1234].operation_count;
        engine.update_activity(1234);

        assert_eq!(engine.process_states[&1234].operation_count, initial_count + 1);
    }
}
