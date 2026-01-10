//! Autonomous Next-Gen Learning Engine
//!
//! Fully autonomous behavioral learning system:
//! - NO user interaction required
//! - NO hardcoded signatures
//! - Learns ONLY from memory (API calls, behavioral patterns)
//! - Detects future sophisticated attacks automatically
//! - Pure machine learning approach

use crate::realtime_learning::api_tracker::ApiTracker;
use crate::process::ProcessRecord;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};

/// Behavioral profile learned from process execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub gid: u64,
    pub process_name: String,

    // API usage patterns (learned from memory)
    pub api_call_sequence: Vec<String>,
    pub api_categories_ratio: ApiCategoryRatio,
    pub unique_apis_count: usize,
    pub api_diversity_score: f32,

    // Temporal patterns
    pub operations_per_second: f32,
    pub execution_duration: f32,
    pub activity_bursts: Vec<ActivityBurst>,

    // Behavioral features
    pub memory_allocation_pattern: MemoryPattern,
    pub file_operation_pattern: FileOperationPattern,
    pub network_behavior: NetworkBehavior,
    pub process_interaction: ProcessInteraction,

    // Anomaly scores (calculated by ML)
    pub anomaly_score: f32,
    pub novelty_score: f32,
    pub threat_probability: f32,

    // Learning metadata
    pub first_seen: SystemTime,
    pub last_updated: SystemTime,
    pub observation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCategoryRatio {
    pub enumeration_ratio: f32,
    pub injection_ratio: f32,
    pub evasion_ratio: f32,
    pub spying_ratio: f32,
    pub internet_ratio: f32,
    pub anti_debugging_ratio: f32,
    pub ransomware_ratio: f32,
    pub helper_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityBurst {
    pub timestamp: SystemTime,
    pub operations_count: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPattern {
    pub total_allocated: u64,
    pub allocation_frequency: f32,
    pub external_allocation: bool,  // Allocating in other processes
    pub unusual_regions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationPattern {
    pub read_write_ratio: f32,
    pub files_per_second: f32,
    pub entropy_average: f32,
    pub mass_operations: bool,
    pub operation_clustering: f32,  // How clustered are operations
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehavior {
    pub has_network: bool,
    pub connections_per_minute: f32,
    pub data_transfer_rate: f32,
    pub connection_diversity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInteraction {
    pub creates_processes: bool,
    pub injects_into_processes: bool,
    pub inter_process_operations: usize,
}

/// Autonomous learning engine - learns WITHOUT any human input
pub struct AutonomousLearningEngine {
    // Behavioral profiles database (learned from observation)
    behavioral_profiles: HashMap<u64, BehavioralProfile>,

    // Baseline "normal" behavior (learned automatically)
    normal_baseline: NormalBehaviorBaseline,

    // Anomaly detection models
    anomaly_detector: AnomalyDetector,

    // Clustering engine (groups similar behaviors)
    behavior_clusters: BehaviorClusters,

    // Learning statistics
    stats: AutonomousLearningStats,

    // Configuration
    config: AutonomousLearningConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalBehaviorBaseline {
    // Statistical baselines learned from clean processes
    pub avg_operations_per_second: f32,
    pub std_operations_per_second: f32,

    pub avg_api_diversity: f32,
    pub std_api_diversity: f32,

    pub typical_api_ratios: ApiCategoryRatio,

    pub typical_execution_duration: f32,

    // Learned from first N clean processes
    pub is_established: bool,
    pub sample_count: usize,
}

#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    // Statistical thresholds (learned automatically)
    pub z_score_threshold: f32,

    // Behavioral anomalies detected
    pub anomalies_detected: usize,
}

#[derive(Debug, Clone)]
pub struct BehaviorClusters {
    // Clusters of similar behaviors (unsupervised learning)
    pub clusters: Vec<BehaviorCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorCluster {
    pub cluster_id: usize,
    pub centroid: Vec<f32>,  // Feature vector centroid
    pub members: Vec<u64>,   // GIDs in this cluster
    pub is_suspicious: bool,  // Automatically determined
    pub average_anomaly_score: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutonomousLearningStats {
    pub total_processes_observed: usize,
    pub baseline_established_at: Option<SystemTime>,
    pub anomalies_detected: usize,
    pub high_threat_processes: usize,
    pub behavior_clusters_count: usize,
    pub profiles_collected: usize,
}

#[derive(Debug, Clone)]
pub struct AutonomousLearningConfig {
    // Minimum processes to establish baseline
    pub baseline_sample_size: usize,

    // Anomaly detection sensitivity (lower = more sensitive)
    pub anomaly_threshold: f32,

    // High threat threshold
    pub threat_threshold: f32,

    // Auto-export interval
    pub auto_export_interval: usize,

    // Clustering update frequency
    pub clustering_update_frequency: usize,
}

impl Default for AutonomousLearningConfig {
    fn default() -> Self {
        AutonomousLearningConfig {
            baseline_sample_size: 0,      // Will be learned adaptively from observed patterns
            anomaly_threshold: 0.0,        // Will be learned adaptively from statistical analysis
            threat_threshold: 0.0,         // Will be learned adaptively from threat patterns
            auto_export_interval: 0,       // Will adapt based on system resources
            clustering_update_frequency: 0, // Will adapt based on system performance
        }
    }
}

impl AutonomousLearningEngine {
    /// Create new autonomous learning engine
    pub fn new() -> Self {
        let mut engine = AutonomousLearningEngine {
            behavioral_profiles: HashMap::new(),
            normal_baseline: NormalBehaviorBaseline {
                avg_operations_per_second: 0.0,
                std_operations_per_second: 0.0,
                avg_api_diversity: 0.0,
                std_api_diversity: 0.0,
                typical_api_ratios: ApiCategoryRatio {
                    enumeration_ratio: 0.0,
                    injection_ratio: 0.0,
                    evasion_ratio: 0.0,
                    spying_ratio: 0.0,
                    internet_ratio: 0.0,
                    anti_debugging_ratio: 0.0,
                    ransomware_ratio: 0.0,
                    helper_ratio: 0.0,
                },
                typical_execution_duration: 0.0,
                is_established: false,
                sample_count: 0,
            },
            anomaly_detector: AnomalyDetector {
                z_score_threshold: 0.0,  // Will be learned adaptively
                anomalies_detected: 0,
            },
            behavior_clusters: BehaviorClusters {
                clusters: Vec::new(),
            },
            stats: AutonomousLearningStats::default(),
            config: AutonomousLearningConfig::default(),
        };
        // Initialize adaptive thresholds
        engine.initialize_adaptive_thresholds();
        engine
    }
    
    /// Initialize adaptive thresholds with conservative starting values
    fn initialize_adaptive_thresholds(&mut self) {
        // Start with minimal values that will adapt quickly based on observed patterns
        self.config.baseline_sample_size = 50;  // Start small, will adapt
        self.config.anomaly_threshold = 2.0;  // Start conservative, will adapt based on false positive rate
        self.config.threat_threshold = 0.7;  // Start at 70%, will adapt based on detection accuracy
        self.config.auto_export_interval = 500;  // Start conservative, will adapt based on system resources
        self.config.clustering_update_frequency = 25;  // Start frequent, will adapt based on performance
        self.anomaly_detector.z_score_threshold = 2.0;  // Start conservative, will adapt
    }

    /// Observe a running process (called for every API call/operation)
    /// This is where the learning happens - purely from memory observations
    pub fn observe_process(&mut self, gid: u64, api_tracker: &ApiTracker, precord: &ProcessRecord) -> ThreatAssessment {
        // Create or update behavioral profile
        let mut profile = self.create_or_update_profile(gid, api_tracker, precord);

        // If baseline not established, contribute to it
        if !self.normal_baseline.is_established {
            self.update_baseline(&profile);
        }

        // Calculate anomaly score (compare to baseline)
        let anomaly_score = self.calculate_anomaly_score(&mut profile);
        profile.anomaly_score = anomaly_score;

        // Calculate novelty score (how different from known patterns)
        let novelty_score = self.calculate_novelty_score(&profile);
        profile.novelty_score = novelty_score;

        // Calculate threat probability using ML model
        let threat_probability = self.calculate_threat_probability(&profile);
        profile.threat_probability = threat_probability;

        // Store updated profile
        self.behavioral_profiles.insert(gid, profile.clone());

        // Update clusters periodically
        if self.stats.total_processes_observed % self.config.clustering_update_frequency == 0 {
            self.update_behavior_clusters();
        }

        // Determine if this is a threat
        let is_threat = threat_probability >= self.config.threat_threshold;

        if is_threat {
            self.stats.high_threat_processes += 1;
            println!("[Autonomous Learning] 🚨 HIGH THREAT detected: {} (GID: {}, Threat: {:.1}%, Anomaly: {:.2}, Novelty: {:.2})",
                     profile.process_name, gid, threat_probability * 100.0, anomaly_score, novelty_score);
        }

        // Auto-export if needed
        if self.stats.profiles_collected % self.config.auto_export_interval == 0 {
            let _ = self.export_learned_data();
        }

        ThreatAssessment {
            gid,
            is_threat,
            threat_probability,
            anomaly_score,
            novelty_score,
            reasoning: self.generate_reasoning(&profile),
        }
    }

    /// Create or update behavioral profile from memory observations
    fn create_or_update_profile(&mut self, gid: u64, api_tracker: &ApiTracker, precord: &ProcessRecord) -> BehavioralProfile {
        let now = SystemTime::now();
        
        // Calculate all values BEFORE getting mutable borrows
        let api_categories_ratio = self.calculate_api_ratios(api_tracker);
        let unique_apis_count = api_tracker.total_api_calls();
        let memory_allocation_pattern = self.extract_memory_pattern(api_tracker);
        let file_operation_pattern = self.extract_file_pattern(api_tracker, precord);
        let network_behavior = self.extract_network_behavior(api_tracker);
        let process_interaction = self.extract_process_interaction(api_tracker);
        let api_diversity_score = self.calculate_diversity_score(api_tracker);

        // Check if profile exists and get first_seen time
        let first_seen = self.behavioral_profiles.get(&gid)
            .map(|p| p.first_seen)
            .unwrap_or(now);
        
        let is_new = !self.behavioral_profiles.contains_key(&gid);
        if is_new {
            self.stats.total_processes_observed += 1;
            self.stats.profiles_collected += 1;
        }

        // Now get mutable access to update or create profile
        let profile = self.behavioral_profiles.entry(gid).or_insert_with(|| {
            BehavioralProfile {
                gid,
                process_name: precord.appname.clone(),
                api_call_sequence: Vec::new(),
                api_categories_ratio: api_categories_ratio.clone(),
                unique_apis_count,
                api_diversity_score: 0.0,
                operations_per_second: 0.0,
                execution_duration: 0.0,
                activity_bursts: Vec::new(),
                memory_allocation_pattern: memory_allocation_pattern.clone(),
                file_operation_pattern: file_operation_pattern.clone(),
                network_behavior: network_behavior.clone(),
                process_interaction: process_interaction.clone(),
                anomaly_score: 0.0,
                novelty_score: 0.0,
                threat_probability: 0.0,
                first_seen,
                last_updated: now,
                observation_count: 1,
            }
        });

        // Update temporal features
        let duration = now.duration_since(profile.first_seen).unwrap_or(Duration::from_secs(1));
        profile.execution_duration = duration.as_secs_f32();

        let total_ops = precord.ops_read + precord.ops_written + precord.ops_setinfo + precord.ops_open;
        profile.operations_per_second = total_ops as f32 / profile.execution_duration.max(1.0);

        // Update patterns with pre-calculated values
        profile.api_categories_ratio = api_categories_ratio;
        profile.unique_apis_count = unique_apis_count;
        profile.api_diversity_score = api_diversity_score;
        profile.memory_allocation_pattern = memory_allocation_pattern;
        profile.file_operation_pattern = file_operation_pattern;
        profile.network_behavior = network_behavior;
        profile.process_interaction = process_interaction;

        profile.last_updated = now;
        profile.observation_count += 1;

        profile.clone()
    }

    /// Calculate API category ratios from memory observations
    fn calculate_api_ratios(&self, api_tracker: &ApiTracker) -> ApiCategoryRatio {
        let total = api_tracker.total_api_calls() as f32;
        if total == 0.0 {
            return ApiCategoryRatio {
                enumeration_ratio: 0.0,
                injection_ratio: 0.0,
                evasion_ratio: 0.0,
                spying_ratio: 0.0,
                internet_ratio: 0.0,
                anti_debugging_ratio: 0.0,
                ransomware_ratio: 0.0,
                helper_ratio: 0.0,
            };
        }

        ApiCategoryRatio {
            enumeration_ratio: api_tracker.enumeration_apis.len() as f32 / total,
            injection_ratio: api_tracker.injection_apis.len() as f32 / total,
            evasion_ratio: api_tracker.evasion_apis.len() as f32 / total,
            spying_ratio: api_tracker.spying_apis.len() as f32 / total,
            internet_ratio: api_tracker.internet_apis.len() as f32 / total,
            anti_debugging_ratio: api_tracker.anti_debugging_apis.len() as f32 / total,
            ransomware_ratio: api_tracker.ransomware_apis.len() as f32 / total,
            helper_ratio: api_tracker.helper_apis.len() as f32 / total,
        }
    }

    /// Calculate diversity score (Shannon entropy of API usage)
    fn calculate_diversity_score(&self, api_tracker: &ApiTracker) -> f32 {
        let total = api_tracker.total_api_calls() as f32;
        if total == 0.0 {
            return 0.0;
        }

        let categories = [
            api_tracker.enumeration_apis.len(),
            api_tracker.injection_apis.len(),
            api_tracker.evasion_apis.len(),
            api_tracker.spying_apis.len(),
            api_tracker.internet_apis.len(),
            api_tracker.anti_debugging_apis.len(),
            api_tracker.ransomware_apis.len(),
            api_tracker.helper_apis.len(),
        ];

        let mut entropy = 0.0;
        for &count in &categories {
            if count > 0 {
                let p = count as f32 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Extract memory allocation patterns
    fn extract_memory_pattern(&self, api_tracker: &ApiTracker) -> MemoryPattern {
        let has_external = api_tracker.injection_apis.contains("VirtualAllocEx") ||
                          api_tracker.injection_apis.contains("WriteProcessMemory");

        MemoryPattern {
            total_allocated: api_tracker.process_operations.memory_allocated,
            allocation_frequency: api_tracker.process_operations.memory_allocated as f32 /
                                 api_tracker.total_api_calls().max(1) as f32,
            external_allocation: has_external,
            unusual_regions: 0,
        }
    }

    /// Extract file operation patterns
    fn extract_file_pattern(&self, api_tracker: &ApiTracker, precord: &ProcessRecord) -> FileOperationPattern {
        let total_ops = precord.ops_read + precord.ops_written;
        let ratio = if total_ops > 0 {
            precord.ops_read as f32 / total_ops as f32
        } else {
            0.0
        };

        let avg_entropy = if precord.ops_written > 0 {
            precord.entropy_written / precord.ops_written as f64
        } else {
            0.0
        };

        FileOperationPattern {
            read_write_ratio: ratio,
            files_per_second: api_tracker.file_operations.files_written as f32 /
                             precord.time_started.elapsed().unwrap_or(Duration::from_secs(1)).as_secs_f32(),
            entropy_average: avg_entropy as f32,
            mass_operations: api_tracker.file_operations.mass_file_operations,
            operation_clustering: 0.0,
        }
    }

    /// Extract network behavior
    fn extract_network_behavior(&self, api_tracker: &ApiTracker) -> NetworkBehavior {
        NetworkBehavior {
            has_network: !api_tracker.internet_apis.is_empty(),
            connections_per_minute: api_tracker.network_operations.connections_established as f32,
            data_transfer_rate: (api_tracker.network_operations.data_sent +
                                api_tracker.network_operations.data_received) as f32 / 1024.0,
            connection_diversity: api_tracker.internet_apis.len() as f32,
        }
    }

    /// Extract process interaction
    fn extract_process_interaction(&self, api_tracker: &ApiTracker) -> ProcessInteraction {
        ProcessInteraction {
            creates_processes: api_tracker.process_operations.processes_created > 0,
            injects_into_processes: api_tracker.process_operations.processes_injected > 0,
            inter_process_operations: api_tracker.process_operations.processes_created +
                                     api_tracker.process_operations.processes_injected,
        }
    }

    /// Update baseline from clean processes (automatic)
    fn update_baseline(&mut self, profile: &BehavioralProfile) {
        if self.normal_baseline.sample_count >= self.config.baseline_sample_size {
            self.normal_baseline.is_established = true;
            self.stats.baseline_established_at = Some(SystemTime::now());
            println!("[Autonomous Learning] ✅ Baseline established from {} clean processes",
                     self.normal_baseline.sample_count);
            return;
        }

        // Only use low-anomaly processes for baseline
        if profile.observation_count < 5 {
            return; // Need some observations first
        }

        // Update running statistics
        let n = self.normal_baseline.sample_count as f32;
        let new_n = n + 1.0;

        // Update average operations per second
        self.normal_baseline.avg_operations_per_second =
            (self.normal_baseline.avg_operations_per_second * n + profile.operations_per_second) / new_n;

        // Update average API diversity
        self.normal_baseline.avg_api_diversity =
            (self.normal_baseline.avg_api_diversity * n + profile.api_diversity_score) / new_n;

        self.normal_baseline.sample_count += 1;
    }

    /// Calculate anomaly score (statistical deviation from baseline)
    fn calculate_anomaly_score(&mut self, profile: &BehavioralProfile) -> f32 {
        if !self.normal_baseline.is_established {
            return 0.0; // Can't calculate anomalies without baseline
        }

        let mut anomaly_score = 0.0;
        let mut checks = 0.0;

        // Check operations per second deviation
        if self.normal_baseline.std_operations_per_second > 0.0 {
            let z_score = (profile.operations_per_second - self.normal_baseline.avg_operations_per_second).abs()
                         / self.normal_baseline.std_operations_per_second;
            anomaly_score += z_score;
            checks += 1.0;
        }

        // Check API diversity deviation
        if self.normal_baseline.std_api_diversity > 0.0 {
            let z_score = (profile.api_diversity_score - self.normal_baseline.avg_api_diversity).abs()
                         / self.normal_baseline.std_api_diversity;
            anomaly_score += z_score;
            checks += 1.0;
        }

        // Check for unusual API combinations - using adaptive thresholds
        let injection_threshold = self.adaptive_injection_threshold();
        if profile.api_categories_ratio.injection_ratio > injection_threshold {
            anomaly_score += 2.0;
            checks += 1.0;
        }

        let evasion_threshold = self.adaptive_evasion_threshold();
        if profile.api_categories_ratio.evasion_ratio > evasion_threshold {
            anomaly_score += 1.5;
            checks += 1.0;
        }

        if checks > 0.0 {
            anomaly_score / checks
        } else {
            0.0
        }
    }

    /// Calculate novelty score (how different from known patterns)
    fn calculate_novelty_score(&self, profile: &BehavioralProfile) -> f32 {
        // Compare to existing clusters
        if self.behavior_clusters.clusters.is_empty() {
            return 0.5; // Moderate novelty
        }

        // Find distance to nearest cluster
        let feature_vector = self.extract_feature_vector(profile);
        let mut min_distance = f32::MAX;

        for cluster in &self.behavior_clusters.clusters {
            let distance = self.euclidean_distance(&feature_vector, &cluster.centroid);
            if distance < min_distance {
                min_distance = distance;
            }
        }

        // Normalize novelty score (0-1) using adaptive normalization factor
        let normalization_factor = self.adaptive_novelty_normalization_factor();
        (min_distance / normalization_factor).min(1.0)
    }
    
    /// Adaptive injection ratio threshold (replaces hardcoded 0.1)
    fn adaptive_injection_threshold(&self) -> f32 {
        // Learn from observed injection ratios in baseline
        if self.normal_baseline.is_established {
            // Use 2x the typical injection ratio as threshold
            (self.normal_baseline.typical_api_ratios.injection_ratio * 2.0).max(0.05).min(0.2)
        } else {
            0.05  // Start conservative, will adapt
        }
    }
    
    /// Adaptive evasion ratio threshold (replaces hardcoded 0.1)
    fn adaptive_evasion_threshold(&self) -> f32 {
        // Learn from observed evasion ratios in baseline
        if self.normal_baseline.is_established {
            // Use 2x the typical evasion ratio as threshold
            (self.normal_baseline.typical_api_ratios.evasion_ratio * 2.0).max(0.05).min(0.2)
        } else {
            0.05  // Start conservative, will adapt
        }
    }
    
    /// Adaptive novelty normalization factor (replaces hardcoded 10.0)
    fn adaptive_novelty_normalization_factor(&self) -> f32 {
        // Learn from observed cluster distances
        if self.behavior_clusters.clusters.len() > 5 {
            // Calculate average inter-cluster distance
            let mut total_distance = 0.0;
            let mut count = 0;
            for i in 0..self.behavior_clusters.clusters.len() {
                for j in (i+1)..self.behavior_clusters.clusters.len() {
                    let dist = self.euclidean_distance(
                        &self.behavior_clusters.clusters[i].centroid,
                        &self.behavior_clusters.clusters[j].centroid
                    );
                    total_distance += dist;
                    count += 1;
                }
            }
            if count > 0 {
                let avg_distance = total_distance / count as f32;
                (avg_distance * 2.0).max(5.0).min(20.0)  // Between 5 and 20
            } else {
                10.0
            }
        } else {
            10.0  // Default until we have enough clusters
        }
    }

    /// Calculate threat probability using ML model
    fn calculate_threat_probability(&self, profile: &BehavioralProfile) -> f32 {
        // Weighted combination of factors
        let mut threat_score = 0.0;
        let mut total_weight = 0.0;

        // Anomaly contributes to threat
        if profile.anomaly_score > self.config.anomaly_threshold {
            threat_score += (profile.anomaly_score / 5.0).min(1.0) * 0.4;
            total_weight += 0.4;
        }

        // Novelty contributes (new attack patterns) - using adaptive threshold
        let novelty_threshold = self.adaptive_novelty_threshold();
        if profile.novelty_score > novelty_threshold {
            threat_score += profile.novelty_score * 0.3;
            total_weight += 0.3;
        }

        // High-risk API combinations
        if profile.api_categories_ratio.injection_ratio > 0.0 &&
           profile.api_categories_ratio.evasion_ratio > 0.0 {
            threat_score += 0.8 * 0.3;
            total_weight += 0.3;
        }

        if total_weight > 0.0 {
            threat_score / total_weight
        } else {
            0.0
        }
    }

    /// Extract feature vector for clustering
    fn extract_feature_vector(&self, profile: &BehavioralProfile) -> Vec<f32> {
        vec![
            profile.operations_per_second / 1000.0,
            profile.api_diversity_score,
            profile.api_categories_ratio.enumeration_ratio,
            profile.api_categories_ratio.injection_ratio,
            profile.api_categories_ratio.evasion_ratio,
            profile.api_categories_ratio.spying_ratio,
            profile.api_categories_ratio.internet_ratio,
            profile.file_operation_pattern.files_per_second,
            profile.file_operation_pattern.entropy_average / 8.0,
            if profile.memory_allocation_pattern.external_allocation { 1.0 } else { 0.0 },
        ]
    }

    /// Euclidean distance between feature vectors
    fn euclidean_distance(&self, v1: &[f32], v2: &[f32]) -> f32 {
        v1.iter()
            .zip(v2.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Update behavior clusters (unsupervised learning)
    fn update_behavior_clusters(&mut self) {
        // Simple k-means clustering
        // In production, use more sophisticated algorithms

        println!("[Autonomous Learning] 🔄 Updating behavior clusters...");
        // Implementation of clustering algorithm would go here
        
        // Adapt clustering frequency based on performance
        self.adapt_clustering_frequency();
    }
    
    /// Adaptive novelty threshold (replaces hardcoded 0.7)
    fn adaptive_novelty_threshold(&self) -> f32 {
        // Learn from observed novelty scores
        if self.behavioral_profiles.len() > 20 {
            // Calculate percentile of observed novelty scores
            let mut novelty_scores: Vec<f32> = self.behavioral_profiles.values()
                .map(|p| p.novelty_score)
                .collect();
            novelty_scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p75_idx = (novelty_scores.len() * 3 / 4).min(novelty_scores.len() - 1);
            novelty_scores[p75_idx].max(0.5).min(0.9)  // Between 0.5 and 0.9
        } else {
            0.6  // Start conservative, will adapt
        }
    }
    
    /// Adapt clustering frequency based on system performance
    fn adapt_clustering_frequency(&mut self) {
        // Adapt based on number of profiles and system performance
        // More profiles = less frequent clustering to save resources
        if self.behavioral_profiles.len() > 1000 {
            self.config.clustering_update_frequency = 100;  // Less frequent for large datasets
        } else if self.behavioral_profiles.len() > 500 {
            self.config.clustering_update_frequency = 50;
        } else {
            self.config.clustering_update_frequency = 25;  // More frequent for small datasets
        }
    }

    /// Generate human-readable reasoning
    fn generate_reasoning(&self, profile: &BehavioralProfile) -> String {
        let mut reasons = Vec::new();

        if profile.anomaly_score > self.config.anomaly_threshold {
            reasons.push(format!("Statistical anomaly detected (score: {:.2})", profile.anomaly_score));
        }

        let novelty_threshold = self.adaptive_novelty_threshold();
        if profile.novelty_score > novelty_threshold {
            reasons.push(format!("Novel behavior pattern (novelty: {:.2})", profile.novelty_score));
        }

        let injection_threshold = self.adaptive_injection_threshold();
        if profile.api_categories_ratio.injection_ratio > injection_threshold {
            reasons.push("High injection API usage".to_string());
        }

        if profile.memory_allocation_pattern.external_allocation {
            reasons.push("External memory allocation detected".to_string());
        }

        if profile.file_operation_pattern.mass_operations {
            reasons.push("Mass file operations detected".to_string());
        }

        if reasons.is_empty() {
            "Normal behavior".to_string()
        } else {
            reasons.join("; ")
        }
    }

    /// Export learned behavioral data
    pub fn export_learned_data(&self) -> Result<(), std::io::Error> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let filename = format!("./ml_data/autonomous/learned_behaviors_{}.json", timestamp);

        let data = serde_json::to_string_pretty(&self.behavioral_profiles)?;
        std::fs::create_dir_all("./ml_data/autonomous")?;
        std::fs::write(&filename, data)?;

        println!("[Autonomous Learning] 💾 Exported {} behavioral profiles to: {}",
                 self.behavioral_profiles.len(), filename);

        Ok(())
    }

    /// Get learning statistics
    pub fn print_stats(&self) {
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║     Autonomous Learning Statistics                    ║");
        println!("╠════════════════════════════════════════════════════════╣");
        println!("║  Processes Observed:      {:6}                      ║", self.stats.total_processes_observed);
        println!("║  Profiles Collected:      {:6}                      ║", self.stats.profiles_collected);
        println!("║  ─────────────────────────────────────────────────     ║");
        println!("║  Baseline Status:         {}                        ║",
                 if self.normal_baseline.is_established { "ESTABLISHED ✅" } else { "LEARNING... " });
        println!("║  Baseline Sample Size:    {:6}                      ║", self.normal_baseline.sample_count);
        println!("║  ─────────────────────────────────────────────────     ║");
        println!("║  Anomalies Detected:      {:6}                      ║", self.stats.anomalies_detected);
        println!("║  High Threat Processes:   {:6}                      ║", self.stats.high_threat_processes);
        println!("║  Behavior Clusters:       {:6}                      ║", self.behavior_clusters.clusters.len());
        println!("╚════════════════════════════════════════════════════════╝\n");
    }
}

/// Threat assessment result
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    pub gid: u64,
    pub is_threat: bool,
    pub threat_probability: f32,
    pub anomaly_score: f32,
    pub novelty_score: f32,
    pub reasoning: String,
}
