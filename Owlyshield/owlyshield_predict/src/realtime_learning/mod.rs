//! OwlyShield Realtime Learning - Advanced Behavioral Analysis and Signature Detection
//!
//! This module provides comprehensive EDR/AV capabilities including:
//! - Dynamic behavioral signature detection
//! - Machine learning data collection
//! - Malware pattern matching (RAT, ransomware, spyware, etc.)
//! - API usage tracking and analysis

pub mod behavioral_signature;
pub mod malware_patterns;
pub mod ml_collector;
pub mod api_tracker;
pub mod realtime_learning;
pub mod autonomous_learning;

pub use behavioral_signature::{SignatureMatch, ThreatLevel};
pub use malware_patterns::{PatternType, PatternMatcher};
pub use ml_collector::MLCollector;
pub use api_tracker::ApiTracker;
pub use realtime_learning::{RealtimeLearningEngine, LearningConfig, LearningLabel};
pub use autonomous_learning::{AutonomousLearningEngine, ThreatAssessment};

use crate::shared_def::IOMessage;
use crate::process::ProcessRecord;
use std::collections::HashMap;

/// Main realtime learning interface for behavioral analysis
pub struct OwlyShieldSDK {
    /// Signature-based detection engine (optional - can be disabled for pure ML)
    pub signature_engine: Option<behavioral_signature::SignatureEngine>,
    /// Pattern matcher for known malware behaviors (optional)
    pub pattern_matcher: Option<PatternMatcher>,
    /// Machine learning data collector
    pub ml_collector: Option<MLCollector>,
    /// Real-time learning engine (auto-learns from running processes)
    pub realtime_learning: Option<RealtimeLearningEngine>,
    /// Autonomous next-gen engine (NO signatures, pure ML from memory)
    pub autonomous_engine: Option<AutonomousLearningEngine>,
    /// API usage tracker per process
    api_trackers: HashMap<u64, ApiTracker>,
    /// Enable ML collection mode
    #[allow(dead_code)]
    ml_mode_enabled: bool,
    /// Enable real-time learning mode
    #[allow(dead_code)]
    realtime_learning_enabled: bool,
    /// Enable autonomous mode (next-gen)
    autonomous_mode_enabled: bool,
}

impl OwlyShieldSDK {
    /// Create a new realtime learning instance
    ///
    /// # Arguments
    /// * `ml_mode_enabled` - Enable machine learning data collection mode
    /// * `malapi_json_path` - Path to malapi.json configuration
    pub fn new(ml_mode_enabled: bool, malapi_json_path: &str, app_settings: &crate::app_settings::AppSettings) -> Self {
        Self::with_realtime_learning(ml_mode_enabled, false, malapi_json_path, app_settings)
    }

    /// Create realtime learning with real-time learning enabled
    ///
    /// # Arguments
    /// * `ml_mode_enabled` - Enable machine learning data collection mode
    /// * `realtime_learning_enabled` - Enable real-time learning from running processes
    /// * `malapi_json_path` - Path to malapi.json configuration
    pub fn with_realtime_learning(ml_mode_enabled: bool, realtime_learning_enabled: bool, malapi_json_path: &str, app_settings: &crate::app_settings::AppSettings) -> Self {
        let signature_engine = Some(behavioral_signature::SignatureEngine::new(malapi_json_path));
        let pattern_matcher = Some(PatternMatcher::new(malapi_json_path));
        let ml_collector = if ml_mode_enabled {
            Some(MLCollector::new())
        } else {
            None
        };
        let realtime_learning = if realtime_learning_enabled {
                        Some(RealtimeLearningEngine::new("./ml_data/realtime", Some(app_settings.win_verify_trust_path.to_str().unwrap())))
        } else {
            None
        };

        OwlyShieldSDK {
            signature_engine,
            pattern_matcher,
            ml_collector,
            realtime_learning,
            autonomous_engine: None,
            api_trackers: HashMap::new(),
            ml_mode_enabled,
            realtime_learning_enabled,
            autonomous_mode_enabled: false,
        }
    }

    /// Create NEXT-GEN realtime learning with autonomous learning (NO hardcoded rules!)
    ///
    /// This mode:
    /// - NO user interaction required
    /// - NO hardcoded signatures
    /// - Learns ONLY from memory (API calls from running processes)
    /// - Detects future sophisticated attacks automatically
    /// - Pure machine learning approach
    ///
    /// # Arguments
    /// * `_malapi_json_path` - Path to malapi.json (only for API categorization)
    pub fn autonomous(_malapi_json_path: &str) -> Self {
        println!("╔═══════════════════════════════════════════════════════════╗");
        println!("║   NEXT-GEN AUTONOMOUS LEARNING MODE ACTIVATED            ║");
        println!("║                                                           ║");
        println!("║   ✓ NO hardcoded signatures                              ║");
        println!("║   ✓ NO user interaction required                         ║");
        println!("║   ✓ Learns from memory (API calls only)                  ║");
        println!("║   ✓ Detects unknown/future attacks                       ║");
        println!("║   ✓ Pure behavioral ML                                   ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        OwlyShieldSDK {
            signature_engine: None,  // NO hardcoded signatures!
            pattern_matcher: None,   // NO hardcoded patterns!
            ml_collector: Some(MLCollector::new()),
            realtime_learning: None,
            autonomous_engine: Some(AutonomousLearningEngine::new()),
            api_trackers: HashMap::new(),
            ml_mode_enabled: true,
            realtime_learning_enabled: false,
            autonomous_mode_enabled: true,
        }
    }

    /// Process an IO message from the kernel driver
    ///
    /// Returns true if malicious behavior is detected
    pub fn process_message(&mut self, msg: &IOMessage, precord: &ProcessRecord) -> bool {
        let gid = msg.gid;

        // Get or create API tracker for this process
        let api_tracker = self.api_trackers
            .entry(gid)
            .or_insert_with(|| ApiTracker::new(gid, precord.appname.clone()));

        // Track API usage from the message
        api_tracker.track_io_operation(msg, precord);

        // Real-time learning: Track process and update activity
        if let Some(ref mut rt_learning) = self.realtime_learning {
            rt_learning.track_process(gid, precord.appname.clone());
            rt_learning.update_activity(gid);
        }

        // AUTONOMOUS MODE: Pure ML detection from memory
        if self.autonomous_mode_enabled {
            if let Some(ref mut autonomous) = self.autonomous_engine {
                let assessment = autonomous.observe_process(gid, api_tracker, precord);

                if assessment.is_threat {
                    println!("[Next-Gen Detection] 🚨 Threat: {} - {}",
                             precord.appname, assessment.reasoning);
                }

                return assessment.is_threat;
            }
        }

        // TRADITIONAL MODE: Signature + Pattern based detection
        let signature_match = if let Some(ref engine) = self.signature_engine {
            engine.check_behavior(api_tracker, precord)
        } else {
            None
        };

        let pattern_match = if let Some(ref matcher) = self.pattern_matcher {
            matcher.match_pattern(api_tracker, precord)
        } else {
            None
        };

        let is_malicious = signature_match.is_some() || pattern_match.is_some();

        // Real-time learning: If malicious detected, mark it
        if is_malicious {
            if let Some(ref mut rt_learning) = self.realtime_learning {
                rt_learning.mark_detected_malicious(gid, api_tracker, precord);
            }
        }

        // Collect data for ML if enabled
        if let Some(ref mut collector) = self.ml_collector {
            collector.collect_sample(api_tracker, precord, is_malicious);
        }

        // Return true if any detection occurred
        is_malicious
    }


    /// Process terminated - final chance to auto-label if benign
    pub fn process_terminated(&mut self, gid: u64) {
        if let Some(ref mut rt_learning) = self.realtime_learning {
            if let Some(api_tracker) = self.api_trackers.get(&gid) {
                let precord = ProcessRecord::new(gid, String::new(), std::path::PathBuf::new());
                rt_learning.process_terminated(gid, api_tracker, &precord);
            }
        }
    }

    /// Periodic check for benign processes (call this every few minutes)
    /// Automatically labels long-running, non-malicious processes as benign
    pub fn check_benign_processes(&mut self, process_records: &HashMap<u64, ProcessRecord>) {
        if let Some(ref mut rt_learning) = self.realtime_learning {
            rt_learning.check_benign_processes(&self.api_trackers, process_records);

            // Auto-export if buffer is full
            if rt_learning.should_export() {
                let _ = rt_learning.export_samples();
            }
        }
    }

    /// Export real-time learning samples
    pub fn export_realtime_samples(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref mut rt_learning) = self.realtime_learning {
            rt_learning.export_samples()
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Real-time learning is not enabled",
            ))
        }
    }

    /// Get real-time learning statistics
    pub fn get_realtime_stats(&self) {
        if let Some(ref rt_learning) = self.realtime_learning {
            rt_learning.print_stats();
        }
    }

    /// Get detailed analysis for a specific process (GID)
    pub fn get_analysis(&self, gid: u64) -> Option<ThreatAnalysis> {
        let api_tracker = self.api_trackers.get(&gid)?;

        let signatures_matched = if let Some(ref engine) = self.signature_engine {
            engine.get_matched_signatures(api_tracker)
        } else {
            Vec::new()
        };

        let patterns_matched = if let Some(ref matcher) = self.pattern_matcher {
            matcher.get_matched_patterns(api_tracker)
        } else {
            Vec::new()
        };

        Some(ThreatAnalysis {
            gid,
            app_name: api_tracker.process_name.clone(),
            api_usage: api_tracker.get_api_usage_summary(),
            signatures_matched,
            patterns_matched,
            threat_level: self.calculate_threat_level(api_tracker),
        })
    }

    /// Get autonomous learning statistics
    pub fn get_autonomous_stats(&self) {
        if let Some(ref autonomous) = self.autonomous_engine {
            autonomous.print_stats();
        } else {
            println!("Autonomous mode is not enabled");
        }
    }

    /// Export autonomous learned data
    pub fn export_autonomous_data(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref mut autonomous) = self.autonomous_engine {
            autonomous.export_learned_rules_to_yaml()
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Autonomous mode is not enabled",
            ))
        }
    }

    /// Calculate overall threat level for a process
    fn calculate_threat_level(&self, api_tracker: &ApiTracker) -> ThreatLevel {
        let signature_matches = if let Some(ref engine) = self.signature_engine {
            engine.get_matched_signatures(api_tracker)
        } else {
            Vec::new()
        };
        let pattern_matches = if let Some(ref matcher) = self.pattern_matcher {
            matcher.get_matched_patterns(api_tracker)
        } else {
            Vec::new()
        };

        if !pattern_matches.is_empty() {
            return ThreatLevel::Critical;
        }

        match signature_matches.len() {
            0 => ThreatLevel::Low,
            1..=2 => ThreatLevel::Medium,
            3..=5 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    /// Export collected ML data to JSON
    pub fn export_ml_data(&self, output_path: &str) -> Result<(), std::io::Error> {
        if let Some(ref collector) = self.ml_collector {
            collector.export_to_json(output_path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "ML collection mode is not enabled",
            ))
        }
    }

    /// Clear tracking data for a specific GID (when process terminates)
    pub fn clear_gid(&mut self, gid: u64) {
        self.api_trackers.remove(&gid);
    }
}

/// Comprehensive threat analysis result
#[derive(Debug, Clone)]
pub struct ThreatAnalysis {
    pub gid: u64,
    pub app_name: String,
    pub api_usage: ApiUsageSummary,
    pub signatures_matched: Vec<SignatureMatch>,
    pub patterns_matched: Vec<PatternType>,
    pub threat_level: ThreatLevel,
}

/// Summary of API usage for a process
#[derive(Debug, Clone)]
pub struct ApiUsageSummary {
    pub enumeration_apis: Vec<String>,
    pub injection_apis: Vec<String>,
    pub evasion_apis: Vec<String>,
    pub spying_apis: Vec<String>,
    pub internet_apis: Vec<String>,
    pub anti_debugging_apis: Vec<String>,
    pub ransomware_apis: Vec<String>,
    pub helper_apis: Vec<String>,
}
