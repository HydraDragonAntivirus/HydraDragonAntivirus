//! MITRE ATT&CK Integration Module
//!
//! Provides comprehensive MITRE ATT&CK framework integration including:
//! - Technique mapping from behaviors
//! - Attack timeline construction  
//! - Threat scoring
//! - JSON-based technique database loading (200+ techniques)
//! - Evidence-based detection with confidence scoring (EDR/XDR grade)
//! - Explainable detections with evidence chains
//!
//! This implementation includes ALL 200+ official MITRE ATT&CK Enterprise techniques
//! loaded from the official MITRE CTI repository JSON database.

pub mod confidence_scoring;
pub mod coverage_analyzer;
pub mod coverage_heatmap;
pub mod evidence_engine;
pub mod evidence_types;
pub mod json_loader;
pub mod scoring;
pub mod stix_updater;
pub mod story_builder;
pub mod technique_mapping;
pub mod timeline;
pub mod timeline_builder;

// Evidence Engine exports (NEW - EDR/XDR grade)
pub use evidence_engine::{DetectionReport, EvidenceEngine, ThreatLevel as EvidenceThreatLevel};
pub use evidence_types::{
    DetectionEvidence, EvidenceBuilder, EvidenceItem, EvidenceSource,
};

// Coverage Analysis exports (NEW)
pub use coverage_analyzer::{CoverageAnalysis, CoverageAnalyzer, CoverageLevel, TacticCoverage, TechniqueCoverage};
pub use coverage_heatmap::CoverageHeatmap;

// Attack Story exports (NEW)
pub use story_builder::{AttackPhase, AttackStory, StoryBuilder};

// Enhanced Confidence Scoring (NEW)
pub use confidence_scoring::{ConfidenceBreakdown, EnhancedConfidenceScorer};

// STIX/TAXII Auto-Updater (NEW)
pub use stix_updater::{AttackVersion, StixTaxiiUpdater, UpdateStatus};

// Original exports
pub use json_loader::load_all_techniques_from_json;
pub use scoring::{CategoryScores, ScoringEngine, ThreatLevel, ThreatScore};
pub use technique_mapping::{MitreTechnique, TechniqueMapper};
pub use timeline::{AttackEvent, AttackTimeline, EventSeverity, TimelineEvent};
pub use timeline_builder::TimelineBuilder;
